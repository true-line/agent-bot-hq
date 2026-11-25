#!/usr/bin/env node
// Render the formula for an already verified public Darwin release artifact.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const [version, archive, approvedSha256, ...extra] = process.argv.slice(2);
if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version ?? '')
  || !archive || !/^[0-9a-f]{64}$/.test(approvedSha256 ?? '') || extra.length) {
  throw new Error('usage: node scripts/build-homebrew-formula.mjs VERSION DARWIN_ARCHIVE APPROVED_SHA256');
}

const artifact = resolve(archive);
const sha256 = createHash('sha256').update(readFileSync(artifact)).digest('hex');
if (sha256 !== approvedSha256) throw new Error('HQ archive does not match the approved SHA-256');

const readArtifactJson = (path) => JSON.parse(execFileSync('tar', ['-xOf', artifact, path], { encoding: 'utf8' }));
const release = readArtifactJson('hq/governance/interim-release.json');
const contracts = readArtifactJson('hq/governance/soul-contracts.json');
if (release.schema_version !== 1 || release.target_platform !== 'darwin'
  || release.owner_control_capability !== 'darwin-owner-control/v2' || contracts.private_candidate) {
  throw new Error('the Homebrew package requires a public Darwin HQ artifact with owner control v2');
}

const asset = `agent-bot-hq-${version}-darwin-arm64.tar`;
process.stdout.write(`class AgentBotHq < Formula
  desc "Local Agent Bot HQ service and owner command"
  homepage "https://github.com/true-line/agent-bot-hq"
  url "https://github.com/true-line/agent-bot-hq/releases/download/v${version}/${asset}", using: :nounzip
  version "${version}"
  sha256 "${sha256}"
  license "MIT"

  depends_on arch: :arm64
  depends_on macos: :sequoia
  depends_on "node"

  def install
    system "/usr/bin/tar", "-xf", "${asset}"
    libexec.install "hq", "${asset}" => "agent-bot-hq-darwin-arm64.tar"
    (bin/"agent-bot-hq").write_env_script Formula["node"].opt_bin/"node", %("#{libexec}/hq/hq/main.mjs"), {}
  end

  def caveats
    <<~EOS
      The archive for Machine's dedicated HQ service setup is:
        #{opt_libexec}/agent-bot-hq-darwin-arm64.tar
      Follow the macOS HQ LaunchDaemon setup in the Agent Bot Machine manual.
    EOS
  end

  test do
    assert_predicate libexec/"agent-bot-hq-darwin-arm64.tar", :file?
    assert_match "darwin-owner-control/v2", shell_output("#{bin}/agent-bot-hq check-owner-control")
  end
end
`);
