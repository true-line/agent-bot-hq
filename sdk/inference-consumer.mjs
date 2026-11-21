import { fail } from './errors.mjs';
import { abortable, inferenceOutput } from './broker-stream.mjs';

// The registered provider adapter supplies authority from HQ and a trusted
// producer. The wire request never supplies a charge limit or credentials.
export async function* runInference({ accounting, authorize, responses, request, caller, signal }) {
  const output = inferenceOutput(request);
  const grant = await abortable(() => authorize(request, caller, signal), signal);
  signal.throwIfAborted();
  if (typeof grant?.soul !== 'string' || !grant.soul.length || !Number.isFinite(grant.maxCost) || grant.maxCost < 0) {
    fail('credential_unavailable', 'no approved operation and cost bound');
  }
  const { task_id, operation_id, destination } = request;
  const claim = await accounting.reserve({ soul: grant.soul, amount: grant.maxCost, runtime_id: caller.runtime_id, task_id, operation_id, destination, signal });
  let started = false;
  let producer;
  let finished = false;
  try {
    signal.throwIfAborted();
    started = true;
    producer = responses(request, grant, signal)[Symbol.asyncIterator]();
    while (true) {
      const event = await abortable(() => producer.next(), signal);
      if (event.done) {
        finished = true;
        const { actualCost, stop_reason, usage } = event.value ?? {};
        const result = request.turn ? { stop_reason, usage } : { usage };
        if (!output.terminal(result) || !Number.isFinite(actualCost) || actualCost < 0) {
          fail('host.internal', 'inference completed without a valid stop, measured usage and cost');
        }
        // Use one HQ-owned snapshot for durable accounting and the reply.
        const measured = { ...usage };
        await accounting.settle(claim, measured, actualCost);
        return { ...result, usage: measured };
      }
      signal.throwIfAborted();
      if (!output.chunk(event.value)) fail('host.internal', 'invalid inference chunk');
      yield event.value;
    }
  } finally {
    if (!started) {
      await accounting.release(claim);
    } else if (!finished) {
      // A producer may ignore cancellation or fail after sending its request.
      // Keep the recorded unknown outcome and ceiling reservation in that case.
      if (producer?.return) Promise.resolve().then(() => producer.return()).catch(() => {});
    }
  }
}
