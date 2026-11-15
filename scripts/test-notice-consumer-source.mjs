#!/usr/bin/env node
// TEST ONLY. This runner checks a reviewed, unreleased source snapshot. It
// never supplies schemas to the production loader or changes a release pin.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { manifestDigest } from './soul-contracts.mjs';

const EXPECTED_COMMIT = '60c540ea71a720148f6733afc7b29fa1ec255753';
const EXPECTED_DIGEST = 'sha256:386efe87f5e1e7751156bdca1a7f8f99ebb266371806b501d712e7011150a697';
const EXPECTED_FILES = 154;
const [source, ...extra] = process.argv.slice(2);
if (!source || extra.length) throw new Error('usage: node scripts/test-notice-consumer-source.mjs <clean-reviewed-soul-contracts-checkout>');
const git = (...args) => execFileSync('git', ['-C', resolve(source), ...args], { maxBuffer: 1 << 28 });
if (git('rev-parse', 'HEAD').toString().trim() !== EXPECTED_COMMIT) throw new Error('test source is not the reviewed notice-contract commit');
if (git('status', '--porcelain', '--untracked-files=all').toString().trim()) throw new Error('test source checkout is not clean');
const entries = git('ls-tree', '-r', '-z', EXPECTED_COMMIT, '--', 'errors', 'fixtures', 'schemas').toString().split('\0').filter(Boolean).map((line) => {
  const [meta, path] = line.split('\t');
  const [mode, type, oid] = meta.split(' ');
  if (type !== 'blob') throw new Error('test source contains a non-blob contract entry');
  return { path, mode, bytes: git('cat-file', 'blob', oid) };
});
const { digest, files } = manifestDigest(entries);
if (digest !== EXPECTED_DIGEST || files !== EXPECTED_FILES) throw new Error('test source does not match the reviewed 154-file contract manifest');
// Parse verified git blobs, not arbitrary working-tree files. Production pin
// verification remains the independent existing soul-contracts.mjs path.
const load = (path) => {
  const entry = entries.find((item) => item.path === path);
  if (!entry) throw new Error(`reviewed test source lacks ${path}`);
  return JSON.parse(entry.bytes.toString('utf8'));
};
const schemas = Object.fromEntries(['notice-query', 'notice-result'].map((name) => [name, load(`schemas/hq/v1/${name}.schema.json`)]));
const fixtures = entries.filter(({ path }) => /^fixtures\/(positive|negative)\/notice-[^/]+\.json$/.test(path)).map(({ path }) => [path, load(path)]);
const { registerNoticeConsumerCases } = await import('../tests/support/notice-consumer-cases.mjs');
registerNoticeConsumerCases(schemas, fixtures);
