// A trusted broker consumer returns this only after authorizing the bound
// operation. The socket opens the producer only for an explicit stream request.
const RESPONSE = Symbol('hq.broker.stream');

export const MODEL_CATALOG = 'inference.models';
export const RESPONSES = 'inference.responses';

const DESTINATION = /^[a-z0-9][a-z0-9.:-]{0,127}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HANDLE = /^[A-Za-z0-9_-]{16,128}$/;
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value) && !value.endsWith('\n');
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));

export function validInferenceRequest(kind, payload) {
  const scope = ['handle', 'destination', 'task_id', 'operation_id'];
  if (!(kind === MODEL_CATALOG || kind === RESPONSES) || !fields(payload, kind === RESPONSES ? [...scope, 'model', 'input'] : scope)) return false;
  return matches(payload.handle, HANDLE) && matches(payload.destination, DESTINATION)
    && matches(payload.task_id, ID) && matches(payload.operation_id, ID)
    && (kind === MODEL_CATALOG || (matches(payload.model, ID) && typeof payload.input === 'string' && payload.input.length > 0));
}

export const validCatalog = (value) => fields(value, ['models']) && Array.isArray(value.models) && value.models.every((model) => matches(model, ID));
export const validDelta = (value) => fields(value, ['type', 'delta']) && value.type === 'response.output_text.delta' && typeof value.delta === 'string';
export const validUsage = (value) => fields(value, ['usage']) && fields(value.usage, ['input_tokens', 'output_tokens'])
  && Object.values(value.usage).every((count) => Number.isSafeInteger(count) && count >= 0);

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
