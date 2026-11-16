// Guarded local notice consumer for Accepted PDR-0062; schemas come from
// the normal digest-verified release loader, as for tasksPlugin.
import { definePlugin } from '../sdk/plugin.mjs';
import { fail } from '../sdk/errors.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { checkRequiredCapabilities } from '../sdk/wire/versions.mjs';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';

export const NOTICE_SCHEMA_NAMES = Object.freeze(['notice-query', 'notice-result']);
const CAPABILITIES = Object.freeze(['notices-v1']);
const MAX_SOURCE_BYTES = 65_536;
const MAX_RESULT_BYTES = 524_288;

export function noticesPlugin({ schemas } = {}) {
  for (const name of NOTICE_SCHEMA_NAMES) if (!schemas?.[name]) throw new TypeError(`notice consumer needs the pinned hq/v1 ${name} schema`);
  const check = (name, value) => {
    const errors = validate(schemas[name], value);
    if (errors.length) fail('host.invalid_request', `invalid hq/v1 ${name}`, { errors: errors.slice(0, 3) });
  };
  const prepare = (request, notices, scope, count) => {
    const result = { contract: 'hq/v1', request_id: request.request_id, operation: request.operation, required_capabilities: [...CAPABILITIES], notices };
    check('notice-result', result);
    if (notices.length > count) fail('host.invalid_request', 'mailbox returned more notices than requested');
    for (const notice of notices) {
      if (notice.content.repo.toLowerCase() !== scope.repo.toLowerCase()) fail('caller_mismatch', 'mailbox returned a notice outside the frozen repository');
      if (canonicalBytes({ id: notice.message_id, ...notice.content }).length > MAX_SOURCE_BYTES) fail('frame_too_large', 'notice source content exceeds the canonical byte budget');
    }
    if (canonicalBytes(result).length > MAX_RESULT_BYTES) fail('frame_too_large', 'notice result exceeds the canonical byte budget');
    return result;
  };
  return definePlugin({
    name: 'hq-notices', version: '0.1.0', hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    optional: { 'agent-comms': '*' },
    async init(ctx) {
      const admission = ctx.deps['hq-admission'];
      if (typeof admission?.withNoticeScope !== 'function') throw new Error('hq-admission does not provide withNoticeScope');
      const mailbox = ctx.deps['agent-comms']?.notices;
      const consume = (operation) => async (request, meta) => {
        // Typed protocol checks precede the closed schema, which is explicitly
        // executed: broker registration alone does not validate its payload.
        if (request?.contract !== 'hq/v1') fail('unsupported_version', 'notice queries require hq/v1');
        if (!Array.isArray(request.required_capabilities)) fail('required_capability_missing', 'notice query requires notices-v1');
        checkRequiredCapabilities(request.required_capabilities, CAPABILITIES);
        checkRequiredCapabilities(CAPABILITIES, request.required_capabilities);
        check('notice-query', request);
        if (request.operation !== operation) fail('caller_mismatch', 'notice operation differs from the broker kind');
        const context = { installation_epoch: request.installation_epoch, lease_generation: request.lease_generation,
          ...(Object.hasOwn(request, 'expected_repository') ? { expected_repository: request.expected_repository } : {}) };
        return admission.withNoticeScope(meta?.runtime_id, context, async (scope) => {
          const method = operation === 'peek' ? 'peek' : 'consumeOne';
          if (typeof mailbox?.[method] !== 'function') fail('host.plugin_degraded', 'scoped local notice mailbox is unavailable');
          const count = request.count ?? 1;
          if (operation === 'peek') {
            const notices = await mailbox.peek({ ...scope, count });
            // Validate every entry before trimming; do not conceal malformed
            // records or oversized individual source content behind a prefix.
            let result;
            try { result = prepare(request, notices, scope, count); }
            catch (error) {
              if (error.code !== 'frame_too_large' || !Array.isArray(notices)) throw error;
              // An individual oversized record still refuses. Only the full
              // aggregate may be reduced by dropping a read-only peek suffix.
              for (const notice of notices) prepare(request, [notice], scope, 1);
              const prefix = [...notices];
              while (prefix.length) {
                prefix.pop();
                try { result = prepare(request, prefix, scope, count); break; }
                catch (again) { if (again.code !== 'frame_too_large') throw again; }
              }
              if (!result) throw error;
            }
            return result;
          }
          let result;
          // Comms calls this synchronously inside its durable transaction,
          // before any tombstone. Schema or budget failure consumes nothing.
          const returned = await mailbox.consumeOne({ ...scope }, (notices) => {
            result = prepare(request, notices, scope, 1);
            return result;
          });
          if (!result || canonicalBytes(returned).compare(canonicalBytes(result.notices)) !== 0) fail('host.invalid_request', 'mailbox did not preserve its prepared notice result');
          return result;
        });
      };
      for (const operation of ['peek', 'consume-one']) ctx.broker.registerKind({ kind: `notices.${operation}`, schema: schemas['notice-query'], consume: consume(operation) });
    },
  });
}
