// Positive-path test driver for the disposable hosted macOS install check.
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  daemonFingerprint, loadMachineSigner, loadOrCreateMachineKey, machineRoundTrip,
  machineSocketPath, pairedPublicKey, pinDaemonPub, verifyResponse,
} from '../../identity/machine-client.mjs';
import { listMembersPlans, readMembersPlan } from '../../identity/machine-members.mjs';

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
  const listed = listMembersPlans().find(plan => plan.plan_id === planId);
  assert.equal(listed?.plan_digest, digest);
  const saved = readMembersPlan({ planId });
  assert.equal(saved.plan_digest, digest);

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
