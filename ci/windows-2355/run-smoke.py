#!/usr/bin/env python3
"""Manual Windows acceptance driver; preparation alone is not an executed result."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

HEAD = '0d17bae1c84d6701397a84cb3ddb05429d955824'
VERSION = '0.15.0-rc.1'
HERE = Path(__file__).resolve().parent


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class SmokeFailure(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def require(condition, message, code='assertion_failed'):
    if not condition:
        raise SmokeFailure(code, message)


def manifest_content_sha(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(encoded.encode('ascii')).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def inventory(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob('*')) if p.is_file()}


def sources(workspace):
    return {'src/' + p: h for p, h in inventory(workspace / 'src').items()} | {
        'v8project.yaml': digest(workspace / 'v8project.yaml')}


def process_identity(pid):
    """Observe an existing PID independently; unavailable is distinct from dead."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        return {'pid': pid, 'alive': False, 'winError': error,
                'observationCode': 'daemon_not_alive' if error == 87 else 'process_open_unavailable'}
    try:
        created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(system), ctypes.byref(user)):
            return {'pid': pid, 'alive': False, 'winError': ctypes.get_last_error(),
                    'observationCode': 'process_times_unavailable'}
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            return {'pid': pid, 'alive': False, 'winError': ctypes.get_last_error(),
                    'observationCode': 'process_exit_unavailable'}
        return {'pid': pid, 'alive': code.value == 259,
                'observationCode': 'ok' if code.value == 259 else 'daemon_not_alive',
                'createdFiletime': (created.dwHighDateTime << 32) | created.dwLowDateTime}
    finally:
        kernel.CloseHandle(handle)


def read_endpoint_bytes(path, limit):
    """Read without conflicting with the daemon's retained DELETE-access handle."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.ReadFile.restype = wintypes.BOOL
    class FileInformation(ctypes.Structure):
        _fields_ = [('attributes', wintypes.DWORD), ('creation', wintypes.FILETIME),
                    ('access', wintypes.FILETIME), ('write', wintypes.FILETIME),
                    ('volume', wintypes.DWORD), ('sizeHigh', wintypes.DWORD), ('sizeLow', wintypes.DWORD),
                    ('links', wintypes.DWORD), ('indexHigh', wintypes.DWORD), ('indexLow', wintypes.DWORD)]
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # GENERIC_READ only; SHARE_READ | SHARE_WRITE | SHARE_DELETE. OPEN_EXISTING:
    # no creation, writes, deletion, ACL changes or inheritable handles.
    # OPEN_REPARSE_POINT prevents reading a symlink target as an endpoint.
    handle = kernel.CreateFileW(str(path), 0x80000000, 0x1 | 0x2 | 0x4,
                                None, 3, 0x00200000 | 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = FileInformation()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(kernel.GetFileType(handle) == 1 and not (information.attributes & (0x10 | 0x400)),
                'Endpoint handle is not a regular non-reparse disk file', 'endpoint_record_not_regular')
        buffer = ctypes.create_string_buffer(limit)
        received = wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, limit, ctypes.byref(received), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw[:received.value]
    finally:
        kernel.CloseHandle(handle)


def published_core_identity(manifest):
    # Frozen identity.rs algorithm of published core ddf0aa7..., not the candidate's API.
    abi = hashlib.sha256(b'unica-v0.13-core-abi-1\0unica-daemon-jsonl-5').hexdigest()
    pin = manifest['artifacts']['unica']['targets']['win-x64']['asset']['sha256']
    return hashlib.sha256(abi.encode('ascii') + b'\0build\0release:' + pin.encode('ascii')).hexdigest()


def observe_daemons(state, expected_identity):
    expected_directory = 'daemon-p5-' + expected_identity
    result = {'summary': {'endpointCount': 0, 'expectedEndpointCount': 0, 'otherEndpointCount': 0,
                           'invalidRecordCount': 0, 'unreadableRecordCount': 0,
                           'expectedNamespacePresent': False, 'processObservationCode': None,
                           'processWinError': None, 'recordReadWinError': None, 'recordReadErrno': None,
                           'endpointReadMethod': 'win32-shared-read', 'scanCode': 'ok'}, 'records': []}
    summary = result['summary']
    try:
        summary['expectedNamespacePresent'] = (state / expected_directory).is_dir()
        paths = sorted(state.rglob('endpoint.json'))
    except OSError:
        summary['scanCode'] = 'endpoint_scan_failed'
        return result
    summary['endpointCount'] = len(paths)
    for path in paths:
        expected_location = path.parent == state / expected_directory
        summary['expectedEndpointCount' if expected_location else 'otherEndpointCount'] += 1
        item = {'path': path.relative_to(state).as_posix(), 'expectedNamespace': expected_location}
        result['records'].append(item)
        try:
            raw = read_endpoint_bytes(path, 16 * 1024 + 1)
        except SmokeFailure as error:
            item['observationCode'] = error.code
            summary['invalidRecordCount'] += 1
            continue
        except OSError as error:
            item['observationCode'] = 'endpoint_record_read_failed'
            item['readWinError'] = getattr(error, 'winerror', None)
            item['readErrno'] = error.errno
            summary['unreadableRecordCount'] += 1
            if expected_location:
                summary['recordReadWinError'] = item['readWinError']
                summary['recordReadErrno'] = item['readErrno']
            continue
        try:
            require(len(raw) <= 16 * 1024, 'Endpoint size exceeds published schema')
            def unique_object(pairs):
                value = {}
                for key, field in pairs:
                    if key in value:
                        raise ValueError('Duplicate JSON key')
                    value[key] = field
                return value
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
            fields = {'schemaVersion', 'protocolVersion', 'coreIdentity', 'pid', 'host', 'port', 'token', 'instanceId'}
            valid = (isinstance(value, dict) and set(value) == fields
                     and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                     and type(value['protocolVersion']) is int and value['protocolVersion'] == 5
                     and isinstance(value['coreIdentity'], str)
                     and re.fullmatch('[0-9a-f]{64}', value['coreIdentity'])
                     and type(value['pid']) is int and 0 < value['pid'] <= 0xffffffff
                     and type(value['port']) is int and 0 < value['port'] <= 65535
                     and value['host'] == '127.0.0.1')
            require(valid, 'Endpoint differs from published schema')
            for field in ['token', 'instanceId']:
                parsed = uuid.UUID(value[field])
                require(parsed.version == 4 and parsed.variant == uuid.RFC_4122, 'Invalid endpoint UUID')
        except (ValueError, TypeError, AttributeError, SmokeFailure):
            item['observationCode'] = 'endpoint_record_invalid'
            summary['invalidRecordCount'] += 1
            continue
        item.update(recordSha256=hashlib.sha256(raw).hexdigest(), pid=value['pid'],
                    coreIdentity=value['coreIdentity'],
                    identityMatchesExpected=value['coreIdentity'] == expected_identity,
                    instanceSha256=hashlib.sha256(value['instanceId'].encode()).hexdigest())
        try:
            item['process'] = process_identity(value['pid'])
        except (OSError, AttributeError, TypeError):
            item['process'] = {'pid': value['pid'], 'alive': False,
                               'observationCode': 'process_identity_unavailable'}
        item['observationCode'] = 'ok'
        if expected_location:
            summary['processObservationCode'] = item['process']['observationCode']
            summary['processWinError'] = item['process'].get('winError')
    return result


def endpoints(state, expected_identity, logs, checkpoint, report):
    observation = observe_daemons(state, expected_identity)
    # Save observations BEFORE assertions, including empty/invalid records; never export raw records.
    save(logs / ('daemon-observation-' + checkpoint + '.json'), observation)
    report['daemonObservation'] = observation['summary']
    if checkpoint == 'after-verify':
        report['verifyDaemonObservation'] = observation['summary']
    summary, records = observation['summary'], observation['records']
    require(summary['scanCode'] == 'ok', 'Cannot enumerate daemon state', 'endpoint_scan_failed')
    require(summary['endpointCount'] > 0, 'No endpoint after verify', 'endpoint_missing')
    require(summary['endpointCount'] == 1, 'Multiple endpoint namespaces found', 'endpoint_ambiguous')
    require(summary['expectedEndpointCount'] == 1, 'Endpoint belongs to a different build namespace',
            'endpoint_namespace_mismatch')
    record = records[0]
    code = record['observationCode']
    require(code == 'ok', 'Cannot validate/read endpoint record', code)
    require(record['identityMatchesExpected'], 'Endpoint identity differs from packaged core',
            'endpoint_namespace_mismatch')
    process = record['process']
    require(process['observationCode'] == 'ok', 'Cannot prove the daemon process is alive',
            process['observationCode'])
    require(process['alive'], 'Daemon process exited', 'daemon_not_alive')
    return records


def same_daemon(before, after):
    require(len(before) == len(after) == 1, 'Expected one daemon endpoint in isolated state')
    require(before == after and before[0]['process']['alive'], 'Daemon changed/exited after verify', 'daemon_replaced')


def attempt_events(cache, artifact):
    events = []
    for path in (cache / '.attempts' / artifact).glob('*.jsonl'):
        for line in path.read_text(encoding='utf-8').splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def installed(cache, manifest, name):
    artifact = manifest['artifacts'][name]
    target = artifact['targets']['win-x64']
    root = cache / name / (artifact['version'] + '--' + target['asset']['sha256']) / 'win-x64'
    ready = json.loads((root / '.ready.json').read_text(encoding='utf-8'))
    require(ready == {'artifact': name, 'version': artifact['version'], 'target': 'win-x64',
                      'assetSha256': target['asset']['sha256']}, 'Invalid ready marker: ' + name)
    for item in target['files']:
        path = (root / item['path']).resolve()
        require(path.is_relative_to(root.resolve()), 'Manifest path escapes installation')
        require(digest(path) == item['sha256'], 'Delivered file SHA mismatch: ' + str(path))
    return root


def no_engines(cache, manifest):
    for name, artifact in manifest['artifacts'].items():
        if artifact['role'] == 'engine':
            require(not (cache / name).exists(), 'Engine installed before diagnostic request: ' + name)
            require(not attempt_events(cache, name), 'Engine delivery attempted before diagnostic request: ' + name)


class MCP:
    def __init__(self, command, cwd, env, logs):
        self.logs = logs
        self.stderr = (logs / 'run-stderr.log').open('wb')
        self.wire = (logs / 'mcp.jsonl').open('w', encoding='utf-8')
        self.child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=self.stderr)
        self.messages = queue.Queue()
        self.counter = 0
        self.workspace = cwd
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        for line in self.child.stdout:
            self.messages.put(line)
        self.messages.put(None)

    def send(self, value):
        self.wire.write(json.dumps({'direction': 'send', 'value': value}, ensure_ascii=False) + '\n')
        self.wire.flush()
        self.child.stdin.write((json.dumps(value, ensure_ascii=False) + '\n').encode('utf-8'))
        self.child.stdin.flush()

    def request(self, method, params=None, timeout=120):
        self.counter += 1
        expected = self.counter
        payload = {'jsonrpc': '2.0', 'id': expected, 'method': method}
        if params is not None:
            payload['params'] = params
        self.send(payload)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('MCP deadline: ' + method)
            line = self.messages.get(timeout=remaining)
            if line is None:
                raise RuntimeError('MCP EOF during ' + method)
            message = json.loads(line)
            self.wire.write(json.dumps({'direction': 'receive', 'value': message}, ensure_ascii=False) + '\n')
            self.wire.flush()
            if 'method' in message and 'id' in message:
                if message['method'] == 'roots/list':
                    self.send({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                        'roots': [{'uri': self.workspace.as_uri(), 'name': 'windows-smoke'}]}})
                elif message['method'] == 'ping':
                    self.send({'jsonrpc': '2.0', 'id': message['id'], 'result': {}})
                else:
                    self.send({'jsonrpc': '2.0', 'id': message['id'], 'error': {
                        'code': -32601, 'message': 'Unsupported client method'}})
                continue
            if message.get('id') == expected:
                return message

    def call(self, name, arguments):
        return self.request('tools/call', {'name': name, 'arguments': arguments})

    def close(self):
        self.child.stdin.close()
        try:
            self.child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=10)
        self.wire.close()
        self.stderr.close()
        return self.child.returncode


def structured(response):
    require('error' not in response, 'MCP RPC error; inspect mcp.jsonl', 'check_rpc_error')
    result = response.get('result', {})
    value = result.get('structuredContent')
    # Some compatible tool responses carry the same structured JSON as text.
    if value is None:
        for block in result.get('content', []):
            if block.get('type') == 'text':
                try:
                    value = json.loads(block['text'])
                except (ValueError, KeyError):
                    continue
                break
    require(isinstance(value, dict), 'No canonical check result; inspect mcp.jsonl', 'check_canonical_result_missing')
    return value


def run(args, report):
    require(os.name == 'nt' and platform.machine().lower() in {'amd64', 'x86_64'}, 'Windows x64 required')
    require(sys.version_info >= (3, 12), 'Python 3.12+ required')
    repo, package, binary = args.candidate_repo.resolve(), args.plugin_root.resolve(), args.bootstrap.resolve()
    require(git(repo, 'rev-parse', 'HEAD') == HEAD, 'Candidate checkout HEAD changed; re-plan compatibility')
    require(not git(repo, 'status', '--porcelain', '--untracked-files=no'), 'Candidate checkout has tracked changes')
    provenance = json.loads(args.build_provenance.read_text(encoding='utf-8-sig'))
    require(provenance['head'] == HEAD and provenance['sha256'].lower() == digest(binary),
            'Candidate binary does not match saved build provenance')
    observed = subprocess.check_output([str(binary), '--version'], text=True).strip()
    require(observed == 'unica-bootstrap ' + VERSION, 'Candidate bootstrap version mismatch')
    manifest_path = package / 'runtime-manifest.json'
    expected_path = HERE / 'published-package-metadata/plugins/unica/runtime-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected_manifest = json.loads(expected_path.read_text(encoding='utf-8'))
    # Git on Windows may materialize release JSON as CRLF. Compare complete JSON content,
    # preserving every artifact pin; also retain the raw file SHA for evidence.
    require(manifest_content_sha(manifest) == manifest_content_sha(expected_manifest),
            'Package manifest content differs from saved published tag')
    require(manifest['pluginVersion'] == VERSION and not manifest['development'], 'Release manifest required')
    for host in ['.codex-plugin', '.claude-plugin', '.zcode-plugin']:
        value = json.loads((package / host / 'plugin.json').read_text(encoding='utf-8'))
        require(value['version'] == VERSION, 'Plugin metadata version mismatch: ' + host)
    require(not (package / 'bin').exists(), 'Use the stock thin package, without bundled core/engines')
    package_commit = git(package, 'rev-parse', 'HEAD')
    require(package_commit == git(package, 'rev-parse', 'v0.15.0-rc.1^{commit}'), 'Package checkout is not the release tag')
    require(not git(package, 'status', '--porcelain', '--untracked-files=no'), 'Stock package has tracked changes')
    # mkdir must fail on any previous scratch: empty cache/state is a hard prerequisite.
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=False)
    logs, cache, state, workspace = [scratch / n for n in ['logs', 'cache', 'state', 'workspace']]
    for p in [logs, cache, state]:
        p.mkdir()
    report['cacheInitiallyEmpty'] = not any(cache.iterdir())
    report['stateInitiallyEmpty'] = not any(state.iterdir())
    require(report['cacheInitiallyEmpty'] and report['stateInitiallyEmpty'], 'Cache/state must start empty')
    report.update({'candidateHead': HEAD, 'candidateBootstrapSha256': digest(binary),
                   'bootstrapVersion': observed, 'publishedCoreSource': manifest['source'],
                   'manifestSha256': digest(manifest_path), 'manifestContentSha256': manifest_content_sha(manifest),
                   'marketplaceCommit': package_commit, 'scratch': str(scratch),
                   'enginePin': manifest['artifacts']['bsl-analyzer'], 'phase': 'verify'})
    save(logs / 'build-provenance.json', provenance)
    shutil.copy2(manifest_path, logs / 'runtime-manifest.json')
    fixture = repo / 'tests/fixtures/acceptance/workspace-diagnostics'
    original = sources(fixture)
    shutil.copytree(fixture, workspace, ignore=shutil.ignore_patterns('.git', '.build', '.session-temp', '__pycache__'))
    baseline = sources(workspace)
    require(original == baseline, 'Fixture copy differs from saved checkout source')
    save(logs / 'sources-before.json', baseline)
    save(logs / 'cache-before.json', inventory(cache))
    save(logs / 'state-before.json', inventory(state))
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('UNICA_')}
    # Do NOT set ARTIFACT_CACHE or RUNTIME_MANIFEST: propagation is precisely the PR under test.
    env.update({'UNICA_RUNTIME_CACHE_DIR': str(cache), 'UNICA_PROVIDER_STATE_DIR': str(state),
                'UNICA_DAEMON_IDLE_GRACE_MS': '60000', 'PYTHONUTF8': '1'})
    expected_identity = published_core_identity(manifest)
    client = None
    try:
        with (logs / 'verify-stdout.log').open('wb') as out, (logs / 'verify-stderr.log').open('wb') as err:
            completed = subprocess.run([str(binary), 'verify', '--plugin-root', str(package)],
                                       cwd=workspace, env=env, stdout=out, stderr=err, timeout=600)
        report['verifyExitCode'] = completed.returncode
        require(completed.returncode == 0, 'Bootstrap verify failed; inspect verify-stderr.log')
        require(sources(workspace) == baseline, 'verify changed source')
        save(logs / 'sources-after-verify.json', sources(workspace))
        no_engines(cache, manifest)
        core_root = installed(cache, manifest, 'unica')
        core_tools = json.loads((core_root / 'third-party/manifest.json').read_text(encoding='utf-8'))
        for tool in core_tools['tools']:
            entry = tool.get('binaries', {}).get('win-x64', tool)
            if tool['name'] != 'unica' and entry.get('binaryPath'):
                require(not (core_root / entry['binaryPath']).exists(), 'External engine bundled into core')
        save(logs / 'core-tools-manifest.json', core_tools)
        report['phase'] = 'verify-daemon'
        before = endpoints(state, expected_identity, logs, 'after-verify', report)
        save(logs / 'daemon-after-verify.json', before)
        report['verifyDaemonCount'] = len(before)
        report['verifyDaemonAlive'] = len(before) == 1 and before[0]['process']['alive']
        if len(before) == 1:
            report['verifyDaemonWinError'] = before[0]['process'].get('winError')
        save(logs / 'cache-after-verify.json', inventory(cache))
        report['phase'] = 'run'
        client = MCP([str(binary), 'run', '--plugin-root', str(package)], workspace, env, logs)
        hello = client.request('initialize', {'protocolVersion': '2025-06-18',
                               'capabilities': {'roots': {'listChanged': False}},
                               'clientInfo': {'name': 'windows-2341-smoke', 'version': '1'}})
        require('result' in hello, 'initialize failed')
        client.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        catalog = client.request('tools/list')
        names = {t['name'] for t in catalog.get('result', {}).get('tools', [])}
        require('unica.check' in names, 'Stock runtime does not expose unica.check')
        same_daemon(before, endpoints(state, expected_identity, logs, 'after-initialize', report))
        no_engines(cache, manifest)
        report['engineAbsentBeforeCheck'] = True
        save(logs / 'cache-before-check.json', inventory(cache))
        report['phase'] = 'check'
        address = 'main:CommonModule.Пример'
        # Fixed saved fixture; no synthetic providers, no injected network/sha failures.
        require((workspace / 'src/CommonModules/Пример/Ext/Module.bsl').is_file(), 'Fixture module missing')
        deadline = time.monotonic() + args.delivery_timeout
        response = client.call('unica.check', {'at': address})
        while True:
            report['checkStage'] = 'response'
            save(logs / 'check-latest.json', response)
            value = structured(response)
            task = (value.get('data') or {}).get('task') or {}
            delivery = (value.get('data') or {}).get('delivery') or {}
            if task.get('status') in {'queued', 'working'}:
                require('unica.task.result' in names, 'No task result tool in compatible catalog')
                require(time.monotonic() < deadline, 'Task deadline expired; result remains incomplete')
                response = client.call('unica.task.result', {'taskId': task['taskId'], 'waitMs': 7000})
            elif delivery.get('artifact') == 'bsl-analyzer' and delivery.get('status') == 'working':
                require(time.monotonic() < deadline, 'Delivery deadline expired; result remains incomplete')
                time.sleep(min(max(delivery.get('retryAfterMs', 1000) / 1000, 0.1), 5))
                response = client.call('unica.check', {'at': address})
            else:
                break
        save(logs / 'check-final.json', response)
        report['checkStage'] = 'daemon'
        after = endpoints(state, expected_identity, logs, 'after-check', report)
        save(logs / 'daemon-after-check.json', after)
        same_daemon(before, after)
        report['checkStage'] = 'delivery-evidence'
        events = attempt_events(cache, 'bsl-analyzer')
        save(logs / 'analyzer-attempt-events.json', events)
        pin = manifest['artifacts']['bsl-analyzer']
        target = pin['targets']['win-x64']
        # The published core compacts closed attempts, including successful installs.
        # A retained 'started' event is diagnostic only, not a completion receipt.
        require(report.get('engineAbsentBeforeCheck') is True, 'Cold engine precondition not proven',
                'check_cold_engine_unproven')
        report['checkStage'] = 'delivery-result'
        if delivery.get('status') == 'failed' and delivery.get('artifact') == 'bsl-analyzer':
            require(delivery.get('failureClass') in {'network', 'untrusted-certificate', 'timeout', 'disk',
                                                    'checksum', 'configuration', 'internal'},
                    'Delivery failure has no real classification', 'check_delivery_class_missing')
            failure_data = value.get('data') or {}
            require(failure_data.get('tool') == 'bsl-analyzer' and failure_data.get('target') == 'win-x64'
                    and failure_data.get('pinnedVersion') == pin['version'],
                    'Typed failure does not prove exact analyzer target/pin', 'check_delivery_target_pin_unproven')
            report['deliveryTargetMatches'] = True
            report['deliveryPinMatches'] = True
            report.update(status='REAL_DELIVERY_FAILURE', exitCode=2, delivery=delivery,
                          deliveryEvidence='typed-delivery-failure',
                          note='Real delivery path reached; successful analyzer execution is NOT proven')
            return
        report['checkStage'] = 'engine-installation'
        engine_root = installed(cache, manifest, 'bsl-analyzer')
        report['engineReadyVerified'] = True
        tool = next(t for t in core_tools['tools'] if t['name'] == 'bsl-analyzer')
        require(tool.get('version') == pin['version'], 'Core tool version differs from release pin',
                'check_engine_version_mismatch')
        entry = tool.get('binaries', {}).get('win-x64', tool)
        report['checkStage'] = 'delivered-path'
        relative = entry.get('deliveredPath')
        require(relative is not None, 'Packaged analyzer has no explicit deliveredPath', 'check_delivered_path_missing')
        engine_binary = (engine_root / relative).resolve()
        require(engine_binary.is_relative_to(engine_root.resolve()), 'deliveredPath escapes own artifact', 'check_delivered_path_escape')
        require(engine_binary != (core_root / entry['binaryPath']).resolve(), 'Analyzer resolved inside core', 'check_delivered_path_in_core')
        report['checkStage'] = 'binary-sha'
        actual_sha = digest(engine_binary)
        require(actual_sha == entry['sha256'], 'deliveredPath SHA differs from packaged tool pin', 'check_packaged_sha_mismatch')
        require(any(f['path'] == relative and f['sha256'] == actual_sha for f in target['files']),
                'deliveredPath SHA differs from release manifest', 'check_release_sha_mismatch')
        report.update(analyzerSha256=actual_sha, analyzerVersion=pin['version'])
        report['deliveredPathPinned'] = True
        report['deliveryEvidence'] = 'fresh-cache-pinned-installation'
        report['checkStage'] = 'terminal-verdict'
        data = value.get('data') or {}
        # Published core records 'bsl' only after a completed full-verdict provider run.
        # Module plans contain only BSL; validators is an array of names, not per-step status objects.
        require(value.get('ok') is True and response.get('result', {}).get('isError') is not True
                and value.get('at') == address and data.get('at') == address
                and data.get('kind') == 'Module' and data.get('status') in {'passed', 'failed'}
                and data.get('validators') == ['bsl'] and isinstance(data.get('diagnostics'), list)
                and not data.get('task') and not data.get('delivery'),
                'No terminal BSL verdict bound to the exact requested Module', 'check_terminal_bsl_unproven')
        report['checkStage'] = 'complete'
        report.update(status='PASS', exitCode=0, deliveredPath=str(engine_binary),
                      analyzerSha256=actual_sha, analyzerVersion=pin['version'], checkAddress=address,
                      note='Candidate bootstrap with the published original core; not an all-head runtime build')
    finally:
        if client is not None:
            report['runExitCode'] = client.close()
            if report['runExitCode'] != 0:
                report.update(status='FAIL_FRONTEND_EXIT', exitCode=1)
        save(logs / 'sources-after.json', sources(workspace))
        report['sourcesUnchanged'] = sources(workspace) == baseline and sources(fixture) == original
        save(logs / 'cache-after.json', inventory(cache))
        save(logs / 'remaining-daemons.json', observe_daemons(state, expected_identity))
        if not report['sourcesUnchanged']:
            report.update(status='FAIL_SOURCE_MUTATION', exitCode=1)
        report['logs'] = str(logs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-repo', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--build-provenance', type=Path, required=True)
    parser.add_argument('--plugin-root', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True, help='Must not exist')
    parser.add_argument('--delivery-timeout', type=int, default=600)
    args = parser.parse_args()
    report = {'status': 'NOT_RUN', 'exitCode': 1}
    try:
        run(args, report)
    except Exception as error:
        status = {'verify': 'BLOCKED_CORE_OR_PACKAGE', 'verify-daemon': 'BLOCKED_DAEMON_OBSERVATION'}.get(
            report.get('phase'), 'FAIL_OR_INCOMPLETE')
        report.update(status=status, exitCode=1,
                      failureCode=error.code if isinstance(error, SmokeFailure) else 'driver_exception',
                      exceptionClass=type(error).__name__, error=type(error).__name__ + ': ' + str(error))
    if report.get('scratch'):
        save(Path(report['scratch']) / 'summary.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report['exitCode']


if __name__ == '__main__':
    sys.exit(main())
