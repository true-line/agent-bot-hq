// Enforcement-profile detection (plan §3.3; platform trust domains and
// profiles; R8). HQ reports the profile actually in force, with the reasons a
// stronger one is not, and never claims more than the host proves.
//
// managed-protected needs every one of these. None exists before §9 PR 16
// (Linux) and PR 29 (macOS), so this skeleton never reports it:
//   - HQ runs in its own OS account (D6: _agent-bot-hq / agent-bot-hq);
//   - each harness credential runs under its own OS account (D7, as amended
//     by platform PDR-0053; PR 16). Whether accounts shared between Souls
//     can earn managed-protected at all is unspecified (platform PDR-0053);
//   - the host passed the hostile-member qualification (T01–T03, T21);
//   - the HQ signer's key is a hardware key, not a key file (§9 PR 15).
//   - HQ started this Soul through the Soul runner (platform PDR-0055).
// Nothing in HQ sets `qualified` yet, so this code never reports
// managed-protected.
// managed-cooperative: the released wire value for cooperative enforcement.
// It does not establish that HQ started the Soul (platform DRIFT-018).
// standalone-unenforced: the owner chose standalone in HQ's config.

export const HQ_ACCOUNTS = Object.freeze({ darwin: '_agent-bot-hq', linux: 'agent-bot-hq' });

export function detectProfile({
  platform = process.platform,
  account,                     // the OS account HQ runs as
  harnessAccounts = false,     // true when every admitted agent runs in its harness's own account
                               // (PR 16 / PR 29); a string ending "(D7)" says which part is missing (hq/hq.mjs)
  qualified = false,           // hostile-member suite passed on this host
  startedByHQ = false,          // per-Soul proof that HQ started its Soul runner; never inferred from enrollment or agent launch
  standalone = false,          // owner config: run standalone, unenforced
  keyFiles,                    // known signer key files in HQ state
  keyStorage,                  // the HQ signer's custody: hardware | software (hq/signer.mjs)
} = {}) {
  const reasons = [];
  const expected = HQ_ACCOUNTS[platform];
  if (!expected) reasons.push(`platform ${platform} has no HQ account defined yet`);
  else if (account !== expected) reasons.push(`HQ runs in the ${account ?? 'unknown'} account, not ${expected} (D6)`);
  if (harnessAccounts !== true) reasons.push(typeof harnessAccounts === 'string' && harnessAccounts ? harnessAccounts : 'agents of every harness share one account: no OS account per harness credential (D7)');
  if (!qualified) reasons.push('the host has not passed the hostile-member qualification (T01–T03, T21)');
  if (keyStorage === 'software') reasons.push('the signer reports software key storage (key_storage=software)');
  else if (keyStorage !== 'hardware') reasons.push('HQ could not verify hardware custody of the device key');
  else if (keyFiles > 0) reasons.push('the previous software signer key file remains in HQ state');
  if (startedByHQ !== true) reasons.push('HQ has not started this Soul through the Soul runner (PDR-0055)');
  if (standalone) return { profile: 'standalone-unenforced', reasons: ['the owner chose standalone in HQ config', ...reasons] };
  // Protected only when every condition holds. The current host-wide caller
  // has no per-Soul start proof or qualification source and falls through.
  if (reasons.length === 0) return { profile: 'managed-protected', reasons };
  return { profile: 'managed-cooperative', reasons };
}

const RANK = { 'standalone-unenforced': 0, 'managed-cooperative': 1, 'managed-protected': 2 };

// R8: a weaker profile than requested is granted only with a warning that
// says so (admission-result.cooperative fixture).
export function profileWarning(requested, inForce, reasons) {
  if (!requested || RANK[inForce] >= RANK[requested]) return undefined;
  const why = reasons.find((r) => r.endsWith('(D7)')) ?? reasons[0] ?? 'containment is not enforced on this host';
  return `profile: ${requested} requested; ${inForce} in force (${why})`.slice(0, 512);
}
