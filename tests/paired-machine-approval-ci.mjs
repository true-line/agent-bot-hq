// Positive-path test driver for the disposable hosted macOS install check.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import {
  daemonFingerprint, loadMachineSigner, loadOrCreateMachineKey, machineRoundTrip,
  machineSocketPath, pairedPublicKey, pinDaemonPub, verifyResponse,
} from '../../identity/machine-client.mjs';
import { MEMBERS_PLAN_DIGEST, MEMBERS_PLAN_ID, membersPlanDigest } from '../../identity/machine-members.mjs';

assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
assert.equal(process.platform, 'darwin');
const [home, channel, action, planId, digest] = process.argv.slice(2);
const context = { home, env: { XDG_STATE_HOME: path.join(home, 'state'), AGENT_MACHINE_DIR: channel } };

if (action === 'prepare') {
  const { publicKeyRaw } = loadOrCreateMachineKey(context);
  pinDaemonPub(context);
  console.log(JSON.stringify({ public: publicKeyRaw.toString('hex'), fingerprint: daemonFingerprint(publicKeyRaw) }));
} else {
  assert.equal(action, 'approve');
  assert.match(planId, MEMBERS_PLAN_ID);
  assert.match(digest, MEMBERS_PLAN_DIGEST);
  const savedFile = path.join(homedir(), 'Library', 'Application Support', 'managed-machine', 'members', 'plans', planId + '.json');
  const saved = JSON.parse(readFileSync(savedFile, 'utf8'));
  assert.equal(saved.plan_id, planId);
  assert.equal(saved.plan_digest, digest);
  assert.equal(membersPlanDigest(saved.plan), digest);

  const { request, reply } = await machineRoundTrip({
    verb: 'approve-members',
    fields: { plan_id: planId, plan_digest: digest },
    signer: loadMachineSigner(context),
    socketPath: machineSocketPath(context),
  });
  const result = verifyResponse(reply, pairedPublicKey(context), { expectedNonce: request.nonce });
  assert.equal(result.ok, true, result.diagnostic + ' ' + result.message);
  assert.equal(result.state, 'approved');
  assert.equal(result.body.plan_id, planId);
  assert.equal(result.body.plan_digest, digest);
  assert.ok(Date.parse(result.body.approved_at) <= Date.now());
  assert.ok(Date.parse(result.body.expires_at) > Date.now());
  console.log(JSON.stringify(result.body));
}
