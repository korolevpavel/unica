#!/usr/bin/env python3
"""Export a closed, path-free proof schema; never copy private logs/state."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HEAD = '9ccfa8f6f92248366df079733718db8f870ea754'
VERSION = '0.15.0-rc.1'
APPROVED_MANIFEST_CONTENT_SHA = '819b9f6ec1b113aadd4b60f96cdb8ea629300ccb2215a60c10220d71c65bcfac'
OFFICIAL_MANIFEST_GIT_BLOB = '5ef90bc66a47521a152c889feb3f037bc40b3450'
ADDRESS = 'main:CommonModule.GoogleПереводчик.Module'
STATUSES = {'BLOCKED_DAEMON_OBSERVATION', 'NOT_EXECUTED', 'PASS', 'REAL_DELIVERY_FAILURE', 'BLOCKED_CORE_OR_PACKAGE',
            'FAIL_OR_INCOMPLETE', 'FAIL_SOURCE_MUTATION', 'FAIL_FRONTEND_EXIT'}
OBSERVATION_CODES = {'ok', 'endpoint_scan_failed', 'endpoint_missing', 'endpoint_ambiguous',
                     'endpoint_namespace_mismatch', 'endpoint_record_read_failed', 'endpoint_record_invalid', 'endpoint_record_not_regular',
                     'process_open_unavailable', 'process_times_unavailable', 'process_exit_unavailable',
                     'process_identity_unavailable', 'daemon_not_alive', 'daemon_replaced'}
FAILURES = {'network', 'untrusted-certificate', 'timeout', 'disk', 'checksum', 'configuration', 'internal'}


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.is_file() else {}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def hex_sha(value, size=64):
    return value if isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) else None


def manifest_content_sha(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(encoded.encode('ascii')).hexdigest()


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
    expected_manifest = load(Path(__file__).resolve().parent / 'published-package-metadata/plugins/unica/runtime-manifest.json')
    observed_manifest = load(logs / 'runtime-manifest.json')
    manifest_matches = (bool(expected_manifest) and bool(observed_manifest)
                        and manifest_content_sha(expected_manifest) == APPROVED_MANIFEST_CONTENT_SHA
                        and manifest_content_sha(observed_manifest) == APPROVED_MANIFEST_CONTENT_SHA
                        and summary.get('manifestSha256') == sha(logs / 'runtime-manifest.json'))
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
    observed_daemon = summary.get('verifyDaemonObservation') or {}
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
        'manifestContentSha256': manifest_content_sha(observed_manifest) if observed_manifest else None,
        'expectedManifestContentSha256': APPROVED_MANIFEST_CONTENT_SHA,
        'officialManifestGitBlob': OFFICIAL_MANIFEST_GIT_BLOB,
        'manifestMatchesPinnedContent': manifest_matches,
        'failurePhase': summary.get('phase') if summary.get('phase') in {'verify', 'verify-daemon', 'run', 'check'} else None,
        'failureCode': summary.get('failureCode') if summary.get('failureCode') in {
            'assertion_failed', 'driver_exception', 'verify_daemon_not_single_live',
            'process_times_unavailable', 'process_exit_unavailable'} | OBSERVATION_CODES else None,
        'exceptionClass': summary.get('exceptionClass') if summary.get('exceptionClass') in {
            'SmokeFailure', 'RuntimeError', 'OSError', 'TimeoutError', 'Empty', 'JSONDecodeError', 'UnicodeDecodeError'} else None,
        'verifyDaemonCount': exit_code(summary.get('verifyDaemonCount')),
        'verifyDaemonAlive': summary.get('verifyDaemonAlive') is True,
        'verifyDaemonWinError': exit_code(summary.get('verifyDaemonWinError')),
        'verifyEndpointCount': exit_code(observed_daemon.get('endpointCount')),
        'verifyExpectedEndpointCount': exit_code(observed_daemon.get('expectedEndpointCount')),
        'verifyOtherEndpointCount': exit_code(observed_daemon.get('otherEndpointCount')),
        'verifyInvalidRecordCount': exit_code(observed_daemon.get('invalidRecordCount')),
        'verifyUnreadableRecordCount': exit_code(observed_daemon.get('unreadableRecordCount')),
        'verifyEndpointReadMethod': 'win32-shared-read'
            if observed_daemon.get('endpointReadMethod') == 'win32-shared-read' else None,
        'verifyEndpointReadWinError': exit_code(observed_daemon.get('recordReadWinError')),
        'verifyEndpointReadErrno': exit_code(observed_daemon.get('recordReadErrno')),
        'verifyExpectedNamespacePresent': observed_daemon.get('expectedNamespacePresent') is True,
        'verifyProcessObservationCode': observed_daemon.get('processObservationCode')
            if observed_daemon.get('processObservationCode') in OBSERVATION_CODES else None,
        'verifyProcessWinError': exit_code(observed_daemon.get('processWinError')),
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
                 'daemon-observation-after-verify.json', 'daemon-observation-after-initialize.json',
                 'daemon-observation-after-check.json',
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
                     and proof['manifestMatchesPinnedContent']
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
            'sameDaemon', 'checkVerdict', 'terminalBslCheck', 'checkTargetMatches', 'deliveryFailureClass', 'analyzerSha256',
            'failurePhase', 'failureCode', 'exceptionClass', 'verifyEndpointCount', 'verifyExpectedEndpointCount',
            'verifyOtherEndpointCount', 'verifyInvalidRecordCount', 'verifyUnreadableRecordCount',
            'verifyExpectedNamespacePresent', 'verifyProcessObservationCode', 'verifyProcessWinError',
            'verifyEndpointReadMethod', 'verifyEndpointReadWinError', 'verifyEndpointReadErrno'])
        + '\nPublished original core + candidate bootstrap. Raw MCP, stderr and state are not uploaded.\n',
        encoding='utf-8')
    (args.out / 'checksums.json').write_text(json.dumps({name: sha(args.out / name)
        for name in ['proof.json', 'proof.md']}, indent=2) + '\n', encoding='utf-8')
    print('Exported closed public proof schema; raw logs and state remain private.')


if __name__ == '__main__':
    main()
