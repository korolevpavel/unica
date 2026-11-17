#!/usr/bin/env python3
"""Export a closed, path-free proof schema; never copy private logs/state."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HEAD = '9ccfa8f6f92248366df079733718db8f870ea754'
VERSION = '0.15.0-rc.1'
ADDRESS = 'main:CommonModule.GoogleПереводчик.Module'
STATUSES = {'NOT_EXECUTED', 'PASS', 'REAL_DELIVERY_FAILURE', 'BLOCKED_CORE_OR_PACKAGE',
            'FAIL_OR_INCOMPLETE', 'FAIL_SOURCE_MUTATION', 'FAIL_FRONTEND_EXIT'}
FAILURES = {'network', 'untrusted-certificate', 'timeout', 'disk', 'checksum', 'configuration', 'internal'}


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.is_file() else {}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def hex_sha(value, size=64):
    return value if isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) else None


def exit_code(value):
    return value if type(value) is int and -2147483648 <= value <= 2147483647 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workflow-sha', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    args = parser.parse_args()
    private = args.private_root
    summary = load(private / 'smoke/summary.json')
    logs = private / 'smoke/logs'
    build = load(private / 'candidate-root/candidate-build.json')
    phase = load(private / 'phase-status.json')
    # Reject arbitrary strings. Only closed enums, numbers, booleans and hashes leave this process.
    status = summary.get('status')
    status = status if status in STATUSES else 'NOT_EXECUTED'
    before, after = load(logs / 'daemon-after-verify.json'), load(logs / 'daemon-after-check.json')
    daemon_ok = (isinstance(before, list) and isinstance(after, list) and len(before) == len(after) == 1
                 and before == after and before[0].get('process', {}).get('alive') is True)
    final = load(logs / 'check-final.json').get('result', {})
    canonical = final.get('structuredContent') or {}
    if not canonical:
        for item in final.get('content', []):
            if item.get('type') == 'text':
                try:
                    value = json.loads(item.get('text', ''))
                except ValueError:
                    continue
                if isinstance(value, dict):
                    canonical = value
                    break
    data = canonical.get('data') or {}
    delivery = summary.get('delivery') or {}
    # Never expose raw error, summary text, path, endpoint, wire, tool arguments or diagnostic messages.
    proof = {
        'schemaVersion': 1, 'repository': 'korolevpavel/unica', 'pr': 2355, 'issue': 2341,
        'workflowCommit': hex_sha(args.workflow_sha, 40),
        'runId': int(args.run_id), 'runAttempt': int(args.run_attempt),
        'expectedCandidateHead': HEAD,
        'builtCandidateHead': build.get('head') if build.get('head') == HEAD else None,
        'bootstrapSha256': hex_sha(build.get('sha256', '').lower()),
        'bootstrapVersionMatches': build.get('version') == 'unica-bootstrap ' + VERSION,
        'publishedCoreVersion': VERSION,
        'publishedCoreSource': 'ddf0aa7c7da9062c2b8a8d1b3f509bf5369faf63',
        'marketplaceCommit': hex_sha(summary.get('marketplaceCommit'), 40),
        'manifestSha256': hex_sha(summary.get('manifestSha256')),
        'status': status,
        'prepareExitCode': exit_code(phase.get('prepareExitCode')),
        'smokeExitCode': exit_code(phase.get('smokeExitCode')),
        'driverExitCode': exit_code(summary.get('exitCode')),
        'verifyExitCode': exit_code(summary.get('verifyExitCode')),
        'frontendExitCode': exit_code(summary.get('runExitCode')),
        'sourcesUnchanged': summary.get('sourcesUnchanged') is True,
        'sameDaemon': daemon_ok,
        'analyzerVersionMatches': summary.get('analyzerVersion') == '0.2.86',
        'analyzerSha256': hex_sha(summary.get('analyzerSha256')),
        'checkOk': canonical.get('ok') is True,
        'checkVerdict': data.get('status') if data.get('status') in {'passed', 'failed'} else None,
        'bslValidatorPresent': data.get('validators') == ['bsl'],
        'checkTargetMatches': canonical.get('at') == ADDRESS and data.get('at') == ADDRESS and data.get('kind') == 'Module',
        'terminalBslCheck': (canonical.get('ok') is True and final.get('isError') is not True
                             and canonical.get('at') == ADDRESS and data.get('at') == ADDRESS
                             and data.get('kind') == 'Module' and data.get('status') in {'passed', 'failed'}
                             and data.get('validators') == ['bsl'] and isinstance(data.get('diagnostics'), list)
                             and not data.get('task') and not data.get('delivery')),
        'deliveryFailureClass': delivery.get('failureClass') if delivery.get('failureClass') in FAILURES else None,
        'privateEvidenceSha256': {},
    }
    # Hash only explicitly named evidence. No filename/path from runtime input is used in exported keys.
    for name in ['build-provenance.json', 'runtime-manifest.json', 'core-tools-manifest.json',
                 'daemon-after-verify.json', 'daemon-after-check.json', 'analyzer-attempt-events.json',
                 'check-final.json', 'sources-before.json', 'sources-after-verify.json', 'sources-after.json',
                 'cache-before.json', 'cache-after-verify.json', 'cache-before-check.json', 'cache-after.json']:
        path = logs / name
        if path.is_file():
            proof['privateEvidenceSha256'][name] = sha(path)
    pass_complete = (status == 'PASS' and all(proof[k] == 0 for k in
                     ['prepareExitCode', 'smokeExitCode', 'driverExitCode', 'verifyExitCode', 'frontendExitCode'])
                     and all(proof[k] for k in ['sourcesUnchanged', 'sameDaemon', 'analyzerVersionMatches',
                                               'bootstrapVersionMatches', 'checkOk', 'bslValidatorPresent', 'checkTargetMatches', 'terminalBslCheck'])
                     and proof['builtCandidateHead'] == HEAD
                     and proof['analyzerSha256'] == '3736453d18dd7ea12634b6a78839eed1fd3a8d821819b752b39f51afd91869d9'
                     and proof['manifestSha256'] == '1d8d93ac358f60e098b31bc94f542e3857502e569df9f9342c750f89695f2034'
                     and proof['checkVerdict'] is not None)
    proof['acceptancePassed'] = bool(pass_complete)
    args.out.mkdir(parents=True, exist_ok=False)
    public_json = args.out / 'proof.json'
    public_json.write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
    verdict = 'PASS' if pass_complete else 'NOT PASSED'
    (args.out / 'proof.md').write_text(
        '# Windows #2355 / #2341: ' + verdict + '\n\n'
        + '| Field | Value |\n| --- | --- |\n'
        + ''.join('| ' + key + ' | ' + str(proof[key]) + ' |\n' for key in [
            'workflowCommit', 'expectedCandidateHead', 'builtCandidateHead', 'status', 'prepareExitCode',
            'smokeExitCode', 'driverExitCode', 'verifyExitCode', 'frontendExitCode', 'sourcesUnchanged',
            'sameDaemon', 'checkVerdict', 'terminalBslCheck', 'checkTargetMatches', 'deliveryFailureClass', 'analyzerSha256'])
        + '\nPublished original core + candidate bootstrap. Raw MCP, stderr and state are not uploaded.\n',
        encoding='utf-8')
    (args.out / 'checksums.json').write_text(json.dumps({name: sha(args.out / name)
        for name in ['proof.json', 'proof.md']}, indent=2) + '\n', encoding='utf-8')
    print('Exported closed public proof schema; raw logs and state remain private.')


if __name__ == '__main__':
    main()
