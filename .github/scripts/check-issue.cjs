// Check report completeness, without downloading or executing submitted files.
const marker = '<!-- ghidart-required-information -->';

function section(body, title) {
  const heading = `### ${title}`;
  const lines = body.split('\n');
  const start = lines.findIndex(line => line.trim() === heading);
  if (start < 0) return '';
  const end = lines.findIndex((line, i) => i > start && /^###? /.test(line));
  return lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
}

function present(text) {
  const content = text.replace(/<!--[\s\S]*?-->/g, '').replace(/[`*_]/g, '').trim();
  return content.length > 0 &&
    !/^(no response|n\/?a|none|unknown|todo|tbd|无|暂无|未知)[.!。]?$/i.test(content);
}

function missingInformation(body) {
  const missing = [];
  for (const [heading, explanation] of [
    ['Problem and reproduction', 'Reproduction steps, the observed problem and expected behavior.'],
    ['Environment', 'ghidart version/commit, Ghidra version, host OS and target OS/architecture.'],
    ['Console log and affected addresses', 'Error/Console output; include an affected function/address when available.']
  ]) {
    if (!present(section(body, heading))) missing.push(explanation);
  }
  const sample = section(body, 'Sample');
  const nonImages = sample.replace(/!\[[^\]]*\]\([^)]*\)/g, '');
  const links = nonImages.match(/https?:\/\/[^\s<>"\])]+/gi) || [];
  if (!present(sample) || !links.some(link =>
    !/\.(png|jpe?g|gif|webp|svg)(?:[?#]|$)/i.test(link) &&
    !/github\.com\/user-attachments\/assets\//i.test(link))) {
    missing.push('The app/package or AOT binary as an attachment/download link (a screenshot alone is not sufficient).');
  }
  return missing;
}

module.exports = async function ({github, context}) {
  const {issue, label} = context.payload;
  if (label && !['bug', 'needs-reproduction', 'enhancement', 'question'].includes(label.name)) return;
  if (!issue || issue.pull_request || issue.state !== 'open') return;
  // The stable watch is a maintenance notice, not a user bug report.
  if (issue.user?.login === 'github-actions[bot]' &&
      issue.body?.includes('<!-- ghidart-dart-stable-watch -->')) return;
  const repo = context.repo;
  const number = issue.number;
  const labels = (issue.labels || []).map(label => typeof label === 'string' ? label : label.name);
  // Form titles cover repositories where custom labels have not been created.
  // Maintainers may reclassify any report as a suggestion/question to exempt it.
  const requiresReproduction = !labels.some(name => ['enhancement', 'question'].includes(name)) &&
    (labels.some(name => ['bug', 'needs-reproduction'].includes(name)) ||
      /^\[(Bug|Analysis support)\]:/i.test(issue.title || ''));
  const missing = requiresReproduction ? missingInformation(issue.body || '') : [];
  const comments = await github.paginate(github.rest.issues.listComments,
    {...repo, issue_number: number, per_page: 100});
  const previous = comments.find(comment => comment.user?.login === 'github-actions[bot]' &&
    comment.body?.includes(marker));
  if (!missing.length && !previous) return;

  const owned = previous?.body.includes('<!-- owns-invalid-label -->') || false;
  let ownsInvalid = owned;
  if (missing.length && !labels.includes('invalid')) {
    try {
      await github.rest.issues.getLabel({...repo, name: 'invalid'});
    } catch (error) {
      if (error.status !== 404) throw error;
      try {
        await github.rest.issues.createLabel({...repo, name: 'invalid', color: 'e4e669',
          description: 'Required reproduction information is missing.'});
      } catch (creationError) {
        if (creationError.status !== 422) throw creationError;
        await github.rest.issues.getLabel({...repo, name: 'invalid'});
      }
    }
    await github.rest.issues.addLabels({...repo, issue_number: number, labels: ['invalid']});
    ownsInvalid = true;
  } else if (!missing.length && owned && labels.includes('invalid')) {
    await github.rest.issues.removeLabel({...repo, issue_number: number, name: 'invalid'});
  }
  const body = missing.length
    ? `${marker}\n${ownsInvalid ? '<!-- owns-invalid-label -->\n' : ''}` +
      'Thanks for reporting this. Could you please edit the issue body to include:\n\n' +
      missing.map(item => `- ${item}`).join('\n') +
      '\n\nThese details are required: without the environment, binary and error/reproduction information, we cannot reproduce or diagnose the problem. The `invalid` label is temporary while the report is incomplete; this issue will remain open. Please use the bug-report or analysis-support form headings. After you update the body, we will check it again automatically.\n\nA sample link is checked for presence only; if it is private or unavailable, we may need further information.'
    : `${marker}\n${requiresReproduction
      ? 'Thanks for adding the required information. The completeness check now passes; the report still needs investigation.'
      : 'This issue is not classified as a bug or binary-analysis support request, so reproduction information is not required.'}
Any temporary label added by this check has been removed.`;
  if (!previous) {
    await github.rest.issues.createComment({...repo, issue_number: number, body});
  } else if (previous.body !== body) {
    await github.rest.issues.updateComment({...repo, comment_id: previous.id, body});
  }
};
module.exports.missingInformation = missingInformation;
