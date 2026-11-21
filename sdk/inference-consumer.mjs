import { fail } from './errors.mjs';
import { abortable, validDelta, validUsage } from './broker-stream.mjs';

// The registered provider adapter supplies authority from HQ and a trusted
// producer. The wire request never supplies a charge limit or credentials.
export async function* runInference({ budgets, store, authorize, responses, request, caller, signal }) {
  const grant = await abortable(() => authorize(request, caller, signal), signal);
  signal.throwIfAborted();
  if (typeof grant?.soul !== 'string' || !Number.isFinite(grant.maxCost) || grant.maxCost < 0) {
    fail('credential_unavailable', 'no approved operation and cost bound');
  }
  const { task_id, operation_id } = request;
  const key = JSON.stringify([grant.soul, task_id, operation_id]);
  const reservation = await budgets.reserve({ soul: grant.soul, amount: grant.maxCost });
  let started = false;
  let recorded = false;
  let producer;
  let finished = false;
  const record = { runtime_id: caller.runtime_id, task_id, operation_id, destination: request.destination, reservation };
  try {
    signal.throwIfAborted();
    // Persist uncertainty before the producer can make an external request.
    await store.tx((tx) => {
      if (tx.get('inference_operations', key)) fail('credential_unavailable', 'the operation already has a record; reconcile before retrying');
      tx.put('inference_operations', key, { ...record, outcome: 'outcome_unknown' });
    });
    recorded = true;
    signal.throwIfAborted();
    started = true;
    producer = responses(request, grant, signal)[Symbol.asyncIterator]();
    while (true) {
      const event = await abortable(() => producer.next(), signal);
      if (event.done) {
        finished = true;
        const { usage, actualCost } = event.value ?? {};
        if (!validUsage({ usage }) || !Number.isFinite(actualCost) || actualCost < 0) fail('host.internal', 'inference completed without measured usage and cost');
        await budgets.settle(reservation, actualCost);
        await store.tx((tx) => tx.put('inference_operations', key, { ...record, outcome: 'completed', usage, actual_cost: actualCost }));
        return { usage };
      }
      signal.throwIfAborted();
      if (!validDelta(event.value)) fail('host.internal', 'invalid inference delta');
      yield event.value;
    }
  } finally {
    if (!started) {
      if (recorded) await store.tx((tx) => tx.delete('inference_operations', key));
      await budgets.release(reservation);
    } else if (!finished) {
      // A producer may ignore cancellation or fail after sending its request.
      // Keep the recorded unknown outcome and ceiling reservation in that case.
      if (producer?.return) Promise.resolve().then(() => producer.return()).catch(() => {});
    }
  }
}
