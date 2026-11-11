import argparse
import json
import sys
import tarfile
import zipfile
from .check import check, load_policy


def main(argv=None):
    parser = argparse.ArgumentParser(description='Check finished Linux ELF release archives without executing them.')
    parser.add_argument('artifact', help='ZIP or tar archive (including compressed tar)')
    parser.add_argument('--policy', required=True, help='JSON policy file')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        result = check(args.artifact, load_policy(args.policy))
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        result = {'schema_version': 1, 'ok': False, 'error': str(exc)}
        code = 2
    else:
        code = 0 if result['ok'] else 1
    if args.format == 'json':
        print(json.dumps(result, indent=2, sort_keys=True))
    elif 'error' in result:
        print('ERROR: ' + repr(result['error']))
    else:
        print(f"{'PASS' if result['ok'] else 'FAIL'}: {result['files_checked']} files, {len(result['binaries'])} ELF binaries")
        for issue in result['issues']:
            # repr prevents hostile filenames or ELF strings from injecting terminal controls.
            print(f"  {issue['code']}: {issue['path']!r}: {issue['message']!r}")
    return code


if __name__ == '__main__':
    sys.exit(main())
