#!/usr/bin/env node
// This module retains the public signature-format conversion. HQ uses its
// paired Machine for Linux device custody.
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// DER ECDSA-Sig-Value → 64 bytes, r then s, each left-padded to 32. Strict:
// short-form lengths only (a P-256 signature never needs more), no trailing
// bytes, positive integers of at most 32 significant bytes.
export function derToP1363(der) {
  const bad = () => new Error('the TPM returned a signature that is not a DER ECDSA signature');
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) throw bad();
  let at = 2;
  const out = Buffer.alloc(64);
  for (const offset of [0, 32]) {
    if (der[at] !== 0x02) throw bad();
    const len = der[at + 1];
    let value = der.subarray(at + 2, at + 2 + len);
    if (len === 0 || len > 33 || value.length !== len || (value[0] & 0x80)) throw bad();
    if (value[0] === 0 && len > 1) { if (!(value[1] & 0x80)) throw bad(); value = value.subarray(1); }
    if (value.length > 32) throw bad();
    value.copy(out, offset + 32 - value.length);
    at += 2 + len;
  }
  if (at !== der.length) throw bad();
  return out;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write('tpm2-signer: HQ device custody requires the paired Machine\n');
  process.exitCode = 1;
}
