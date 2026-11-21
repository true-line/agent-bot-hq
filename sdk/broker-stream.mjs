import { exactFields as fields, readStream, validStructuredTurn, validToolChunk } from './inference-turn.mjs';

// A trusted broker consumer returns this only after authorizing the bound
// operation. The socket opens the producer only for an explicit stream request.
const RESPONSE = Symbol('hq.broker.stream');

export const MODEL_CATALOG = 'inference.models';
export const RESPONSES = 'inference.responses';

const DESTINATION = /^[a-z0-9][a-z0-9.:-]{0,127}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HANDLE = /^[A-Za-z0-9_-]{16,128}$/;
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value) && !value.endsWith('\n');
export function validInferenceRequest(kind, payload) {
  const scope = ['handle', 'destination', 'task_id', 'operation_id'];
  const base = kind === MODEL_CATALOG ? scope : [...scope, 'model'];
  if (kind === RESPONSES) {
    if (!fields(payload, [...base, 'input']) && !fields(payload, [...base, 'turn'])) return false;
    if (!matches(payload.model, ID)) return false;
    const validInput = Object.hasOwn(payload, 'turn') ? validStructuredTurn(payload.turn)
      : typeof payload.input === 'string' && payload.input.length > 0;
    if (!validInput) return false;
  } else if (kind !== MODEL_CATALOG || !fields(payload, base)) return false;
  return matches(payload.handle, HANDLE) && matches(payload.destination, DESTINATION)
    && matches(payload.task_id, ID) && matches(payload.operation_id, ID);
}

export const validCatalog = (value) => fields(value, ['models']) && Array.isArray(value.models) && value.models.every((model) => matches(model, ID));
const validDelta = (value) => fields(value, ['type', 'delta']) && value.type === 'response.output_text.delta' && typeof value.delta === 'string';
const validUsage = (value) => fields(value, ['input_tokens', 'output_tokens'])
  && Object.values(value).every((count) => Number.isSafeInteger(count) && count >= 0);

const terminalUsage = (value) => fields(value, ['usage']) && validUsage(value.usage);

export const validOutputChunk = (value) => validDelta(value) || validToolChunk(value);
export const validOutputTerminal = (value) => terminalUsage(value) || (fields(value, ['stop_reason', 'usage'])
  && ['end_turn', 'tool_use'].includes(value.stop_reason) && validUsage(value.usage));

export function inferenceOutput(request) {
  if (!request.turn) return { chunk: validDelta, terminal: terminalUsage };
  const stream = readStream(request.turn.messages.length === 1);
  return {
    chunk: (value) => validDelta(value) ? stream.text() : stream.tool(value),
    terminal: (value) => fields(value, ['stop_reason', 'usage']) && validUsage(value.usage)
      && stream.stop(value.stop_reason),
  };
}

export function brokerStream(open) {
  if (typeof open !== 'function') throw new TypeError('broker stream needs a producer');
  return Object.freeze({ [RESPONSE]: open });
}

export const brokerStreamProducer = (result) => result?.[RESPONSE];

export async function abortable(work, signal) {
  signal.throwIfAborted();
  let abort;
  const stopped = new Promise((_, reject) => {
    abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
  });
  try { return await Promise.race([work(), stopped]); }
  finally { signal.removeEventListener('abort', abort); }
}
