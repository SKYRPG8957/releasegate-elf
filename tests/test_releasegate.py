import contextlib
import io
import json
import random
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

from releasegate.archive import read_archive
from releasegate.check import check, load_policy
from releasegate.elf import inspect_elf, InvalidELF
from releasegate.__main__ import main


def elf(machine=62, versions=('GLIBC_2.34', 'GLIBCXX_3.4.29'), needed=('libc.so.6',), bits=64, endian='<'):
    """Synthetic ELF fixture, not a redistributable historical project binary."""
    strings = bytearray(b'\0')
    def put(value):
        offset = len(strings)
        strings.extend(value.encode() + b'\0')
        return offset
    lib = put('libc.so.6')
    deps = [put(x) for x in needed]
    names = [put(x) for x in versions]
    data = bytearray(1024)
    data[:16] = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1]) + bytes(9)
    def pack(fmt, offset, *values):
        struct.pack_into(endian + fmt, data, offset, *values)
    hdrsize, phsize = (64, 56) if bits == 64 else (52, 32)
    tags = [(5, 512), (10, len(strings))] + [(1, d) for d in deps]
    if versions:
        tags += [(0x6ffffffe, 640), (0x6fffffff, 1)]
    tags += [(0, 0)]
    dsize = len(tags) * (16 if bits == 64 else 8)
    if bits == 64:
        pack('HHIQQQIHHHHHH', 16, 3, machine, 1, 0, hdrsize, 0, 0, hdrsize, phsize, 2, 0, 0, 0)
        pack('IIQQQQQQ', hdrsize, 1, 5, 0, 0, 0, len(data), len(data), 4096)
        pack('IIQQQQQQ', hdrsize + phsize, 2, 4, 256, 256, 0, dsize, dsize, 8)
    else:
        pack('HHIIIIIHHHHHH', 16, 3, machine, 1, 0, hdrsize, 0, 0, hdrsize, phsize, 2, 0, 0, 0)
        pack('IIIIIIII', hdrsize, 1, 0, 0, 0, len(data), len(data), 5, 4096)
        pack('IIIIIIII', hdrsize + phsize, 2, 256, 256, 0, dsize, dsize, 4, 4)
    for i, (tag, val) in enumerate(tags):
        pack('qQ' if bits == 64 else 'iI', 256 + i * (16 if bits == 64 else 8), tag, val)
    data[512:512 + len(strings)] = strings
    if versions:
        pack('HHIII', 640, 1, len(versions), lib, 16, 0)
        for i, name in enumerate(names):
            pack('IHHII', 656 + i * 16, 0, 0, 2 + i, name, 16 if i < len(names) - 1 else 0)
    return bytes(data)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = {'schema_version': 1, 'architecture': 'x86_64', 'max_glibc': '2.28', 'max_glibcxx': '3.4.25'}

    def archive(self, entries, zip=False):
        path = self.root / ('release.zip' if zip else 'release.tar.gz')
        if zip:
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
                for name, data, mode in entries:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | mode) << 16
                    z.writestr(info, data)
        else:
            with tarfile.open(path, 'w:gz') as t:
                for name, data, mode in entries:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), mode
                    t.addfile(info, io.BytesIO(data))
        return path

    def codes(self, entries, policy=None, **kwargs):
        return {x['code'] for x in check(self.archive(entries, **kwargs), policy or self.policy)['issues']}

    def test_glibc_regression_class(self):
        self.assertIn('max_glibc', self.codes([('bin/app', elf(versions=('GLIBC_2.34',)), 0o755)]))

    def test_glibcxx_regression_class(self):
        self.assertIn('max_glibcxx', self.codes([('bin/app', elf(versions=('GLIBCXX_3.4.29',)), 0o755)]))

    def test_equal_baseline_passes(self):
        self.assertFalse(self.codes([('bin/app', elf(versions=('GLIBC_2.28', 'GLIBCXX_3.4.25')), 0o755)]))

    def test_version_numeric_not_lexical(self):
        self.assertFalse(self.codes([('bin/app', elf(versions=('GLIBC_2.9',)), 0o755)]))

    def test_unknown_glibc_version_fails_closed(self):
        self.assertIn('unrecognized_version', self.codes([('app', elf(versions=('GLIBC_PRIVATE',)), 0o755)]))

    def test_architecture(self):
        self.assertIn('architecture', self.codes([('app', elf(machine=183, versions=()), 0o755)]))

    def test_32bit_big_endian(self):
        info = inspect_elf(elf(machine=40, bits=32, endian='>'))
        self.assertEqual((info['architecture'], info['bits']), ('arm', 32))
        self.assertEqual(info['versions'][0]['name'], 'GLIBC_2.34')

    def test_required_permissions_dependencies(self):
        policy = dict(self.policy, required_files=['assets/default.cfg'], executables=['bin/app'], runtime_dependencies=['libc.so.6'])
        codes = self.codes([('bin/app', elf(versions=(), needed=('libc.so.6', 'libSDL2-2.0.so.0')), 0o644)], policy)
        self.assertEqual(codes, {'missing_file', 'not_executable', 'undeclared_dependency'})

    def test_zip_permissions(self):
        policy = dict(self.policy, executables=['app'])
        self.assertFalse(self.codes([('app', elf(versions=()), 0o755)], policy, zip=True))
        self.assertIn('not_executable', self.codes([('app', elf(versions=()), 0o644)], policy, zip=True))

    def test_no_elf_and_opt_out(self):
        self.assertEqual(self.codes([('README', b'text', 0o644)]), {'no_elf'})
        self.assertFalse(self.codes([('README', b'text', 0o644)], dict(self.policy, require_elf=False)))

    def test_malformed_elf(self):
        self.assertEqual(self.codes([('app', b'\x7fELF', 0o755)]), {'invalid_elf', 'no_elf'})

    def test_all_truncations_rejected_cleanly(self):
        for i in range(1024):
            with self.subTest(length=i), self.assertRaises(InvalidELF):
                inspect_elf(elf()[:i])

    def test_deterministic_mutations_fail_cleanly(self):
        rng = random.Random(42)
        original = elf()
        for _ in range(5000):
            data = bytearray(original)
            for _ in range(rng.randrange(1, 8)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                inspect_elf(data)
            except InvalidELF:
                pass

    def test_architecture_class_mismatch(self):
        with self.assertRaises(InvalidELF):
            inspect_elf(elf(machine=62, bits=32))

    def test_traversal_and_absolute_paths(self):
        for name in ('../escape', '/tmp/escape', 'x/../../escape', 'C:/escape', 'x\\escape', 'bad\nname'):
            for zip in (False, True):
                with self.subTest(name=name, zip=zip), self.assertRaises(ValueError):
                    read_archive(self.archive([(name, b'x', 0o644)], zip=zip))
        self.assertFalse((self.root.parent / 'escape').exists())

    def test_root_directory_entries(self):
        # GNU tar commonly includes ./ when packaging a directory's contents.
        for root_name in ('.', './'):
            for zipped in (False, True):
                with self.subTest(root_name=root_name, zipped=zipped):
                    path = self.root / ('root.zip' if zipped else 'root.tar')
                    if zipped:
                        with zipfile.ZipFile(path, 'w') as archive:
                            archive.writestr(root_name + '/', b'')
                            archive.writestr('./README', b'release notes')
                    else:
                        with tarfile.open(path, 'w') as archive:
                            root = tarfile.TarInfo(root_name)
                            root.type = tarfile.DIRTYPE
                            archive.addfile(root)
                            item = tarfile.TarInfo('./README')
                            item.size = len(b'release notes')
                            archive.addfile(item, io.BytesIO(b'release notes'))
                    self.assertEqual(set(read_archive(path)), {'README'})
        for root_name in ('.', './'):
            with self.subTest(root_name=root_name), self.assertRaises(ValueError):
                read_archive(self.archive([(root_name, b'x', 0o644)]))

    def test_cli_invalid_architecture_types(self):
        path = self.root / 'policy.json'
        for architecture in ([], {}, None, 42, True):
            path.write_text(json.dumps(dict(self.policy, architecture=architecture)))
            output = io.StringIO()
            with self.subTest(architecture=architecture), contextlib.redirect_stdout(output):
                code = main(['unused.tar', '--policy', str(path), '--format', 'json'])
            self.assertEqual(code, 2)
            self.assertIn('architecture must be', json.loads(output.getvalue())['error'])

    def test_duplicate_normalized_paths(self):
        with self.assertRaises(ValueError):
            read_archive(self.archive([('app', b'x', 0o644), ('./app', b'y', 0o644)]))

    def test_file_cannot_also_be_parent_directory(self):
        for zipped in (False, True):
            for entries in (
                [('app', b'file', 0o644), ('app/config.json', b'{}', 0o644)],
                [('app/config.json', b'{}', 0o644), ('app', b'file', 0o644)],
                [('app', b'file', 0o644), ('app/assets/config.json', b'{}', 0o644)],
                [('app/assets/config.json', b'{}', 0o644), ('./app', b'file', 0o644)],
            ):
                with self.subTest(zipped=zipped, paths=[e[0] for e in entries]):
                    with self.assertRaisesRegex(ValueError, 'file/directory conflict'):
                        read_archive(self.archive(entries, zip=zipped))

    def test_cli_reports_file_directory_conflict_as_input_error(self):
        artifact = self.archive([('app', b'file', 0o644),
                                 ('app/config.json', b'{}', 0o644)])
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps(dict(self.policy, require_elf=False)))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(artifact), '--policy', str(policy), '--format', 'json'])
        self.assertEqual(code, 2)
        result = json.loads(output.getvalue())
        self.assertFalse(result['ok'])
        self.assertIn('file/directory conflict', result['error'])

    def test_deep_zip_path_does_not_expand_all_parent_prefixes(self):
        # One legal ZIP member can contain thousands of path components.
        name = 'a/' * 16000 + 'file'
        self.assertEqual(set(read_archive(self.archive([(name, b'x', 0o644)], zip=True))),
                         {name})

    def test_similar_path_prefixes_are_not_conflicts(self):
        for zipped in (False, True):
            with self.subTest(zipped=zipped):
                path = self.archive([('app', b'file', 0o644),
                                     ('application/config.json', b'{}', 0o644)], zip=zipped)
                self.assertEqual(len(read_archive(path)), 2)

    def test_explicit_directories_can_follow_their_contents(self):
        for zipped in (False, True):
            with self.subTest(zipped=zipped):
                path = self.root / ('directories.zip' if zipped else 'directories.tar')
                if zipped:
                    with zipfile.ZipFile(path, 'w') as archive:
                        archive.writestr('app/assets/config.json', b'{}')
                        archive.writestr('app/', b'')
                        archive.writestr('app/assets/', b'')
                else:
                    with tarfile.open(path, 'w') as archive:
                        item = tarfile.TarInfo('app/assets/config.json')
                        item.size = 2
                        archive.addfile(item, io.BytesIO(b'{}'))
                        for name in ('app', 'app/assets'):
                            item = tarfile.TarInfo(name)
                            item.type = tarfile.DIRTYPE
                            archive.addfile(item)
                self.assertEqual(set(read_archive(path)), {'app/assets/config.json'})

    def test_links_rejected(self):
        path = self.root / 'link.tar'
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with tarfile.open(path, 'w') as t:
                item = tarfile.TarInfo('app')
                item.type, item.linkname = kind, '../../outside'
                t.addfile(item)
            with self.assertRaises(ValueError):
                read_archive(path)
        with zipfile.ZipFile(self.root / 'link.zip', 'w') as z:
            item = zipfile.ZipInfo('app')
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(item, '../../outside')
        with self.assertRaises(ValueError):
            read_archive(self.root / 'link.zip')

    def test_size_limit(self):
        from unittest.mock import patch
        with patch('releasegate.archive.MAX_FILE', 2), self.assertRaises(ValueError):
            read_archive(self.archive([('large', b'abc', 0o644)]))

    def test_entry_limit(self):
        from unittest.mock import patch
        with patch('releasegate.archive.MAX_ENTRIES', 1), self.assertRaises(ValueError):
            read_archive(self.archive([('one', b'', 0o644), ('two', b'', 0o644)]))

    def test_policy_validation(self):
        bad = [[], {}, dict(self.policy, max_glibc='latest'), dict(self.policy, max_glibc=2.28), dict(self.policy, typo=True), dict(self.policy, executables='../app'), dict(self.policy, required_files=['../app']), dict(self.policy, runtime_dependencies=['/lib/libc.so.6']), dict(self.policy, require_elf=1), dict(self.policy, schema_version=True)]
        for value in bad:
            path = self.root / 'policy.json'
            path.write_text(json.dumps(value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_policy(path)

    def test_cli_exit_codes_json(self):
        policy = self.root / 'policy.json'
        policy.write_text(json.dumps(self.policy))
        for versions, expected in [((), 0), (('GLIBC_2.34',), 1)]:
            artifact = self.archive([('app', elf(versions=versions), 0o755)])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(artifact), '--policy', str(policy), '--format', 'json'])
            self.assertEqual(code, expected)
            self.assertEqual(json.loads(output.getvalue())['ok'], expected == 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['missing.tar', '--policy', str(policy)]), 2)

    @unittest.skipUnless(shutil.which('gcc') and shutil.which('readelf'), 'needs GCC and readelf')
    def test_real_compiled_elf_without_execution(self):
        source = self.root / 'app.c'
        source.write_text('#include <stdio.h>\nint main(void) { puts("never execute fixture"); return 0; }\n')
        binary = self.root / 'app'
        subprocess.run(['gcc', str(source), '-o', str(binary)], check=True, capture_output=True)
        info = inspect_elf(binary.read_bytes())
        reference = subprocess.run(['readelf', '-dV', str(binary)], check=True, capture_output=True, text=True).stdout
        self.assertIn('libc.so.6', info['needed'])
        self.assertTrue(info['versions'])
        for version in info['versions']:
            self.assertIn(version['name'], reference)
        self.assertFalse(self.codes([('app', binary.read_bytes(), 0o755)], dict(self.policy, max_glibc='999.0')))


if __name__ == '__main__':
    unittest.main()
