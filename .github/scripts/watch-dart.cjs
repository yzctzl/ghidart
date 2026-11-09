// Only official stable metadata is fetched; no SDK archives or AI services.
const fs = require('node:fs');
const marker = '<!-- ghidart-dart-stable-watch -->';

function versionParts(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`Expected a stable Dart version, got ${version}`);
  }
  return version.split('.').map(Number);
}

function newer(a, b) {
  const x = versionParts(a), y = versionParts(b);
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] > y[i];
  }
  return false;
}

module.exports = async function ({github, context, core, fetchVersion = async () => {
  const response = await fetch(
    'https://storage.googleapis.com/dart-archive/channels/stable/release/latest/VERSION',
    {signal: AbortSignal.timeout(30000)});
  if (!response.ok) throw new Error(`Dart metadata HTTP ${response.status}`);
  return response.json();
}}) {
  const baseline = JSON.parse(fs.readFileSync('.github/compatibility.json', 'utf8'));
  const latest = await fetchVersion();
  const advanced = newer(latest.version, baseline.dart_stable);
  if (newer(baseline.dart_stable, latest.version)) {
    throw new Error('Official stable metadata is older than the validated baseline');
  }
  if (!/^[0-9a-f]{40}$/.test(latest.revision)) {
    throw new Error('Missing or malformed official Dart revision');
  }
  if (latest.version === baseline.dart_stable && latest.revision !== baseline.dart_revision) {
    throw new Error('Stable version matches, but its revision differs from the validated baseline');
  }
  const summary = `Validated stable: **${baseline.dart_stable}**. ` +
    `Latest stable: **${latest.version}**. ` +
    (advanced ? 'Compatibility work is pending.' : 'No newer stable release.');
  await core.summary.addHeading('Dart stable compatibility').addRaw(summary).write();
  const repo = context.repo;
  const issues = await github.paginate(github.rest.issues.listForRepo,
    {...repo, state: 'all', creator: 'github-actions[bot]', per_page: 100});
  const issue = issues.find(i => !i.pull_request && i.body?.includes(marker));
  if (!advanced) {
    if (issue?.state === 'open') {
      await github.rest.issues.update({...repo, issue_number: issue.number, state: 'closed'});
    }
    return;
  }
  const body = `${marker}
${summary}

- Official revision: [${latest.revision}](https://github.com/dart-lang/sdk/commit/${latest.revision})
- [SDK changes](https://github.com/dart-lang/sdk/compare/${baseline.dart_stable}...${latest.version})
- [Official SDK archive](https://dart.dev/get-dart/archive)

Use the local \`ghidart-sdk-compatibility\` skill to advance from ${baseline.dart_stable} to ${latest.version}.
Review snapshot serialization and ARM64 codegen changes, then run normal/obfuscated ARM64 acceptance and historical format-family regression. Record parsing, boundaries, character XREFs and native C delivery separately.

This is an update notice, not a compatibility failure or a successful acceptance. No SDK is downloaded and no agent is invoked. Advance \`.github/compatibility.json\` only after actual acceptance. Beta/dev are not monitored.
`;
  const title = `Dart stable compatibility: ${baseline.dart_stable} → ${latest.version}`;
  if (!issue) {
    await github.rest.issues.create({...repo, title, body});
  } else if (issue.title !== title || issue.body !== body || issue.state !== 'open') {
    await github.rest.issues.update({...repo, issue_number: issue.number, title, body, state: 'open'});
  }
};
