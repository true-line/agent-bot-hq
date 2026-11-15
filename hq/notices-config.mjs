// HQ's owner-written configuration for the broker's identity-service queues.
// Content, custody and polling live in agent-bot-comms, behind host services.
const DAY = 24 * 60 * 60 * 1000;
const RANGES = { pollIntervalMs: [1000, 3600_000], count: [1, 50], leaseSeconds: [10, 3600], maxMessages: [1, 100_000], maxBytes: [64 * 1024, 1024 * 1024 * 1024], retentionMs: [7 * DAY, 90 * DAY] };

export function validateNoticesConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('HQ config: notices is an object');
  const allowed = new Set(['harnesses', 'wakeClass', 'scopes', ...Object.keys(RANGES)]);
  for (const name of Object.keys(input)) if (!allowed.has(name)) throw new Error(`HQ config: unknown key notices.${name}`);
  if (!Array.isArray(input.harnesses) || input.harnesses.length < 1 || input.harnesses.length > 32
    || input.harnesses.some((h) => typeof h !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$(?![\s\S])/.test(h)) || new Set(input.harnesses).size !== input.harnesses.length) throw new Error('HQ config: notices.harnesses is a unique list of 1 to 32 harness names');
  for (const [name, [lo, hi]] of Object.entries(RANGES)) if (input[name] !== undefined && (!Number.isSafeInteger(input[name]) || input[name] < lo || input[name] > hi)) throw new Error(`HQ config: notices.${name} must be an integer from ${lo} to ${hi}`);
  if (input.wakeClass !== undefined && !['none', 'notify'].includes(input.wakeClass)) throw new Error('HQ config: notices.wakeClass is none or notify');
  if (input.scopes !== undefined) {
    if (!Array.isArray(input.scopes) || input.scopes.length > 1024) throw new Error('HQ config: notices.scopes is a list of at most 1024 exact assignments');
    const seen = new Set();
    for (const row of input.scopes) {
      if (!validNoticeAssignment(row) || Object.keys(row).length !== ASSIGNMENT_FIELDS.length + 2
        || Object.keys(row).some((key) => ![...ASSIGNMENT_FIELDS, 'harness', 'repo'].includes(key))
        || !input.harnesses.includes(row.harness) || !validNoticeScope(row)) throw new Error('HQ config: notices.scopes needs an exact accepted assignment and configured harness/repository');
      const key = JSON.stringify(ASSIGNMENT_FIELDS.map((field) => row[field]));
      if (seen.has(key)) throw new Error('HQ config: duplicate notices.scopes assignment');
      seen.add(key);
    }
  }
  return input;
}

// These are owner-local selectors over already schema-checked admission data;
// no adapter id or OS account is inferred to name a remote harness.
// JavaScript `$` also matches before a final line terminator. Require the
// absolute end so owner policy and query assertions use the same syntax.
const ASSIGNMENT_FIELDS = ['soul_id', 'definition_digest', 'member_id', 'adapter_id', 'role'];
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/;
export const validNoticeScope = (scope) => !!scope && typeof scope === 'object'
  && typeof scope.harness === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$(?![\s\S])/.test(scope.harness)
  && validNoticeRepository(scope.repo);
export const validNoticeRepository = (repo) => typeof repo === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$(?![\s\S])/.test(repo);
const validNoticeAssignment = (row) => !!row && typeof row === 'object' && !Array.isArray(row)
  && typeof row.soul_id === 'string' && /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$(?![\s\S])/.test(row.soul_id)
  && typeof row.definition_digest === 'string' && /^sha256:[0-9a-f]{64}$(?![\s\S])/.test(row.definition_digest)
  && typeof row.member_id === 'string' && ID.test(row.member_id)
  && typeof row.adapter_id === 'string' && ID.test(row.adapter_id)
  && typeof row.role === 'string' && /^[a-z][a-z0-9-]{0,31}$(?![\s\S])/.test(row.role);

export function resolveNoticeScope(notices, assignment, allowsHarness) {
  const row = notices?.scopes?.find((candidate) => ASSIGNMENT_FIELDS.every((field) => candidate[field] === assignment[field]));
  if (!row || !allowsHarness(row.harness)) return null;
  return Object.freeze({ harness: row.harness, repo: row.repo });
}

// Scope mappings stay private to HQ admission; comms receives only ingestion
// settings, so it cannot reinterpret assignment policy or admission tables.
export function noticeIngestionConfig(notices) {
  if (!notices) return null;
  const { scopes, ...ingestion } = notices;
  return ingestion;
}
