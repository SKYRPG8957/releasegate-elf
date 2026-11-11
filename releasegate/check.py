import json
import re
from .archive import read_archive, safe_name
from .elf import inspect_elf, InvalidELF


VERSION = re.compile(r'[0-9]+(?:\.[0-9]+)*\Z')


def version_tuple(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError('versions must be numeric dotted strings')
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (8 - len(parts))


def load_policy(path):
    with open(path, encoding='utf-8') as f:
        policy = json.load(f)
    if not isinstance(policy, dict):
        raise ValueError('policy must be an object')
    allowed = {'schema_version', 'architecture', 'max_glibc', 'max_glibcxx', 'required_files', 'executables', 'runtime_dependencies', 'require_elf'}
    unknown = set(policy) - allowed
    if unknown:
        raise ValueError('unknown policy keys: ' + ', '.join(sorted(unknown)))
    if type(policy.get('schema_version')) is not int or policy['schema_version'] != 1:
        raise ValueError('schema_version must be 1')
    if not isinstance(policy.get('architecture'), str) or policy['architecture'] not in {'x86', 'x86_64', 'arm', 'aarch64', 'riscv'}:
        raise ValueError('architecture must be x86, x86_64, arm, aarch64 or riscv')
    for key in ('max_glibc', 'max_glibcxx'):
        if key in policy:
            version_tuple(policy[key])
    for key in ('required_files', 'executables', 'runtime_dependencies'):
        values = policy.get(key, [])
        if not isinstance(values, list) or not all(isinstance(x, str) and x for x in values):
            raise ValueError(key + ' must be a list of nonempty strings')
        if key != 'runtime_dependencies':
            for value in values:
                if safe_name(value) != value:
                    raise ValueError('policy paths must be normalized relative paths')
        elif any('/' in x or '\\' in x for x in values):
            raise ValueError('runtime_dependencies must contain SONAMEs, not paths')
    if 'require_elf' in policy and type(policy['require_elf']) is not bool:
        raise ValueError('require_elf must be a boolean')
    return policy


def check(artifact, policy):
    files = read_archive(artifact)
    issues, binaries = [], []

    def issue(code, path, message):
        issues.append({'code': code, 'path': path, 'message': message})

    for path in sorted(set(policy.get('required_files', []) + policy.get('executables', []))):
        if path not in files:
            issue('missing_file', path, 'Required file is absent from archive')
    for path in policy.get('executables', []):
        if path in files and not files[path][1] & 0o111:
            issue('not_executable', path, 'Archive does not preserve any executable permission bit')
    for path, (data, _) in sorted(files.items()):
        if not data.startswith(b'\x7fELF'):
            continue
        try:
            binary = inspect_elf(data)
        except InvalidELF as exc:
            issue('invalid_elf', path, str(exc))
            continue
        binary['path'] = path
        binaries.append(binary)
        if binary['architecture'] != policy['architecture']:
            issue('architecture', path, f"Expected {policy['architecture']}, found {binary['architecture']}")
        for requirement in binary['versions']:
            name = requirement['name']
            for prefix, key in (('GLIBC_', 'max_glibc'), ('GLIBCXX_', 'max_glibcxx')):
                if not name.startswith(prefix) or key not in policy:
                    continue
                value = name[len(prefix):]
                if not VERSION.fullmatch(value):
                    issue('unrecognized_version', path, f'{name} cannot be compared to {key}; review manually')
                elif version_tuple(value) > version_tuple(policy[key]):
                    issue(key, path, f"Requires {name} from {requirement['library']}; allowed maximum is {policy[key]}")
        if 'runtime_dependencies' in policy:
            for library in binary['needed']:
                if library not in policy['runtime_dependencies']:
                    issue('undeclared_dependency', path, f'{library} is a DT_NEEDED dependency absent from runtime_dependencies')
    if policy.get('require_elf', True) and not binaries:
        issue('no_elf', '', 'No readable ELF binary found')
    return {'schema_version': 1, 'artifact': str(artifact), 'ok': not issues, 'files_checked': len(files), 'binaries': binaries, 'issues': issues}
