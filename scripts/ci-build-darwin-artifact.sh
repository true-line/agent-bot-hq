#!/usr/bin/env bash
# Build one macOS-targeted source archive at the checkout's exact source SHA.
set -euo pipefail
source_sha="${1:?HQ commit required}"
output="${2:?output tar required}"
contracts="$(mktemp -d)"
trap 'rm -rf "$contracts"' EXIT
contracts="$(cd "$contracts" && pwd -P)"
node --input-type=module - "$contracts" <<'JS'
import { cpSync } from 'node:fs';
import { join } from 'node:path';
import { readPin, verify, verifyVendored } from './scripts/soul-contracts.mjs';

const pin = readPin();
const source = verify().dir;
const target = process.argv[2];
for (const path of pin.paths) cpSync(join(source, path), join(target, path), { recursive: true });
verifyVendored(target, pin);
JS
node scripts/build-interim-release.mjs "$source_sha" "$contracts" "$output" --target darwin
