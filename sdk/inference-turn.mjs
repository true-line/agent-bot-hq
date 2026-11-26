// The private draft supports the measured single Read round trip. Tool
// declarations and transcripts are data for the provider, not local actions.
import { parseStrict } from './wire/strict-json.mjs';

const CALL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PROPERTY = /^[a-z][a-z0-9_]{0,63}$/;
const TEXT_LIMIT = 32 * 1024;
const PATH_LIMIT = 1024;
const ARGUMENT_LIMIT = 8 * 1024;
const MAX_OUTPUT_TOKENS = 128_000;
const BLOCK_LIMIT = 8;

const isRecord = (value) => value && typeof value === 'object' && !Array.isArray(value);
export const exactFields = (value, names) => isRecord(value)
  && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const onlyFields = (value, required, optional) => isRecord(value)
  && required.every((name) => Object.hasOwn(value, name))
  && Object.keys(value).every((name) => required.includes(name) || optional.includes(name));

const text = (value, limit = TEXT_LIMIT) => typeof value === 'string' && Buffer.byteLength(value) <= limit;
const boundedText = (value, limit) => text(value, limit) && value.length > 0;
const validCallId = (value) => typeof value === 'string' && CALL_ID.test(value) && !value.endsWith('\n');
const readInput = (input) => exactFields(input, ['file_path']) && boundedText(input.file_path, PATH_LIMIT)
  && input.file_path.startsWith('/') && !input.file_path.includes('\0');

function readProperty(schema) {
  const { type, description, minimum, maximum, exclusiveMinimum, exclusiveMaximum } = schema ?? {};
  return onlyFields(schema, ['type'], ['description', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'])
    && ['string', 'number', 'integer', 'boolean'].includes(type)
    && (description === undefined || text(description))
    && [minimum, maximum, exclusiveMinimum, exclusiveMaximum].every((bound) => bound === undefined
      || (['number', 'integer'].includes(type) && Number.isFinite(bound)));
}

function readTool(tool) {
  if (!onlyFields(tool, ['name', 'description', 'input_schema'], ['strict']) || tool.name !== 'Read'
      || !text(tool.description) || ('strict' in tool && typeof tool.strict !== 'boolean')) return false;
  const schema = tool.input_schema;
  if (!onlyFields(schema, ['type', 'properties', 'required'], ['additionalProperties', '$schema'])
      || schema.type !== 'object' || !isRecord(schema.properties)
      || ('additionalProperties' in schema && schema.additionalProperties !== false)
      || ('$schema' in schema && !['http://json-schema.org/draft-07/schema#', 'https://json-schema.org/draft/2020-12/schema'].includes(schema.$schema))
      || !Array.isArray(schema.required) || schema.required.length !== 1 || schema.required[0] !== 'file_path'
      || schema.properties.file_path?.type !== 'string') return false;
  const properties = Object.entries(schema.properties);
  return properties.length <= 12 && properties.every(([name, property]) => PROPERTY.test(name)
    && !name.endsWith('\n') && readProperty(property));
}

const validCache = (cache) => onlyFields(cache, ['type'], ['ttl']) && cache.type === 'ephemeral'
  && (!Object.hasOwn(cache, 'ttl') || ['5m', '1h'].includes(cache.ttl));
const optionalCache = (block) => !Object.hasOwn(block, 'cache_control') || validCache(block.cache_control);
const textBlock = (block) => onlyFields(block, ['type', 'text'], ['cache_control']) && block.type === 'text'
  && text(block.text) && optionalCache(block);
const blockList = (value) => Array.isArray(value) && value.length > 0 && value.length <= BLOCK_LIMIT;
const textContent = (value) => text(value) || (blockList(value) && value.every(textBlock));
const toolUse = (block) => onlyFields(block, ['type', 'id', 'name', 'input'], ['cache_control'])
  && block.type === 'tool_use' && validCallId(block.id) && block.name === 'Read'
  && readInput(block.input) && optionalCache(block);
const toolResult = (block, call) => onlyFields(block, ['type', 'tool_use_id', 'content'], ['is_error', 'cache_control'])
  && block.type === 'tool_result' && block.tool_use_id === call.id && textContent(block.content)
  && (!Object.hasOwn(block, 'is_error') || typeof block.is_error === 'boolean') && optionalCache(block);

function oneToolBlock(message, role, type, validate) {
  if (!exactFields(message, ['role', 'content']) || message.role !== role || !blockList(message.content)) return undefined;
  const blocks = message.content.filter((block) => block?.type === type);
  if (blocks.length !== 1 || !validate(blocks[0])) return undefined;
  return message.content.every((block) => block === blocks[0] || textBlock(block)) ? blocks[0] : undefined;
}

export function validStructuredTurn(turn) {
  if (!exactFields(turn, ['system', 'max_output_tokens', 'tools', 'messages'])
      || !textContent(turn.system) || !Number.isSafeInteger(turn.max_output_tokens)
      || turn.max_output_tokens <= 0 || turn.max_output_tokens > MAX_OUTPUT_TOKENS
      || !Array.isArray(turn.tools) || turn.tools.length !== 1 || !readTool(turn.tools[0])
      || !Array.isArray(turn.messages) || ![1, 3].includes(turn.messages.length)) return false;
  const [user, assistant, result] = turn.messages;
  if (!exactFields(user, ['role', 'content']) || user.role !== 'user' || !textContent(user.content)) return false;
  if (turn.messages.length === 1) return true;
  const call = oneToolBlock(assistant, 'assistant', 'tool_use', toolUse);
  return !!(call && oneToolBlock(result, 'user', 'tool_result', (block) => toolResult(block, call)));
}

export function validToolChunk(value) {
  switch (value?.type) {
    case 'response.tool_call.start':
      return exactFields(value, ['type', 'call_id', 'name']) && validCallId(value.call_id) && value.name === 'Read';
    case 'response.tool_call.arguments.delta':
      return exactFields(value, ['type', 'call_id', 'delta']) && validCallId(value.call_id)
        && boundedText(value.delta, ARGUMENT_LIMIT);
    default:
      return false;
  }
}

export function readStream(initial) {
  let call;
  let textSeen = false;
  let argumentsJson = '';
  return {
    text() {
      if (call) return false;
      textSeen = true;
      return true;
    },
    tool(chunk) {
      if (!initial || !validToolChunk(chunk)) return false;
      if (chunk.type === 'response.tool_call.start') {
        if (call || textSeen) return false;
        call = chunk.call_id;
        return true;
      }
      if (chunk.call_id !== call || Buffer.byteLength(argumentsJson + chunk.delta) > ARGUMENT_LIMIT) return false;
      argumentsJson += chunk.delta;
      return true;
    },
    stop(reason) {
      if (reason === 'end_turn') return !call;
      if (reason !== 'tool_use' || !call) return false;
      try { return readInput(parseStrict(argumentsJson, { maxDepth: 1 })); }
      catch { return false; }
    },
  };
}
