import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { hInventoryDigest, verifyStage2aHEnvelope } from '../hq/stage2a-h-preloader.mjs';

const purpose = 'agent-bot/stage2a-h-service-descriptor/v3';
const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const node = process.execPath;
const preloader = fileURLToPath(new URL('../hq/stage2a-h-preloader.mjs', import.meta.url));
const digest = 'sha256:' + 'a'.repeat(64);
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pin = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const unixOnly = { skip: process.platform === 'win32' };

test('H inventory digest uses the domain purpose, not the sidecar file hash', () => {
  const bytes = Buffer.from('{"a":1}');
  assert.equal(hInventoryDigest(bytes),
    'sha256:b508b7a0cb8c85e19b756e6b87e5c7f476170686c0aba25b092ab2d31a362bf9');
  assert.notEqual(hInventoryDigest(bytes), sha(bytes));
});

function fixture(change = () => {}) {
  const argv = [node, '--no-addons', '--disallow-code-generation-from-strings',
    '--import', preloader, '/selected/hq/main.mjs', 'run', '--owner-account', 'owner'];
  const payload = {
    contract: 'machine/v3', kind: 'stage2a-h-service-descriptor', schema_version: 3,
    host_id: 'host', hq_installation_id: 'hq', owner_plan_digest: digest,
    h_inventory: {
      contract: 'machine/v3', kind: 'stage2a-inventory-ref', schema_version: 3,
      domain: 'H-code', installation_id: 'hq', owner_plan_digest: digest,
      reviewed_source_inventory_digest: digest, machine_uid: 400,
      reader_uid: process.getuid(), reader_gid: process.getgid(),
      snapshot: {}, sidecar: {}, file_count: 1, directory_count: 0,
      total_bytes: 1, inventory_digest: digest,
    },
    components: [{ component_id: 'hq', release_artifact_sha256: digest,
      release_attestation_sha256: digest, release_manifest_sha256: digest }],
    outer_launch: {
      ruby_path: '/usr/bin/ruby', ruby_sha256: digest,
      helper_path: '/selected/helpers/darwin-owner.rb', helper_sha256: digest,
      argv: ['/usr/bin/ruby', '--disable-gems', '/selected/helpers/darwin-owner.rb',
        'launch', ...argv],
    },
    runtime: {
      node_path: node, node_sha256: digest, preloader_path: preloader,
      preloader_sha256: digest, entry_path: '/selected/hq/main.mjs',
      entry_sha256: digest, guard_module_path: '/selected/hq/stage2a-selected-code.mjs',
      guard_module_sha256: digest, argv,
    },
  };
  change(payload);
  const bytes = Buffer.from(canonicalize(payload));
  const preimage = Buffer.concat([Buffer.from(purpose + '\0'), bytes]);
  const envelope = {
    schema_version: 3, purpose, issuer_public_key_base64url: pin.toString('base64url'),
    payload_sha256: sha(bytes), payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, preimage, privateKey).toString('base64url'),
  };
  return { raw: Buffer.from(canonicalize(envelope)), argv, descriptorDigest: sha(preimage) };
}

test('H preloader verifies the exact A-signed payload and purpose digest', unixOnly, () => {
  const { raw, argv, descriptorDigest } = fixture();
  assert.equal(verifyStage2aHEnvelope(raw, pin, argv).descriptorDigest, descriptorDigest);
});

test('H preloader refuses a forged key, changed argv, helper and plugin override', unixOnly, () => {
  const { raw, argv } = fixture();
  assert.throws(() => verifyStage2aHEnvelope(raw, Buffer.alloc(32), argv), /unavailable/);
  assert.throws(() => verifyStage2aHEnvelope(raw, pin, argv.slice(0, -1)), /unavailable/);
  for (const change of [
    (p) => { p.outer_launch.argv[2] = '/other/helper.rb'; },
    (p) => { p.outer_launch.argv.splice(5, 1); },
    (p) => { p.runtime.argv.push('--plugins', '/owner/plugins'); p.outer_launch.argv.push('--plugins', '/owner/plugins'); },
    (p) => { p.h_inventory.owner_plan_digest = 'sha256:' + 'b'.repeat(64); },
  ]) {
    const changed = fixture(change);
    assert.throws(() => verifyStage2aHEnvelope(changed.raw, pin, changed.argv), /unavailable/);
  }
});

test('H preloader refuses noncanonical envelope bytes and changed signature', unixOnly, () => {
  const { raw, argv } = fixture();
  assert.throws(() => verifyStage2aHEnvelope(Buffer.concat([raw, Buffer.from('\n')]), pin, argv), /unavailable/);
  const changed = JSON.parse(raw);
  changed.signature_base64url = Buffer.alloc(64).toString('base64url');
  assert.throws(() => verifyStage2aHEnvelope(Buffer.from(canonicalize(changed)), pin, argv), /unavailable/);
});

test('the real --import entry refuses before HQ runs without installed A metadata', () => {
  const child = spawnSync(node, ['--no-addons',
    '--disallow-code-generation-from-strings', '--import', preloader,
    '--eval', 'console.log("unverified H launch reached HQ")'],
  { encoding: 'utf8', timeout: 5000 });
  assert.notEqual(child.status, 0);
  assert.doesNotMatch(child.stdout, /unverified H launch reached HQ/);
});
