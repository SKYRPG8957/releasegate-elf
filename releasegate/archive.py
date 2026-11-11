"""Inspect archives in memory, without extracting paths or following links."""
import stat
import tarfile
import zipfile
from pathlib import PurePosixPath

MAX_TOTAL = 512 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_ENTRIES = 10000


def safe_name(name):
    if not name or '\\' in name or '\x00' in name or any(ord(c) < 32 for c in name):
        raise ValueError('unsafe archive path')
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or (p.parts and ':' in p.parts[0]):
        raise ValueError('unsafe archive path: ' + repr(name))
    normalized = str(p)
    if normalized == '.':
        return ''
    return normalized


def read_archive(path):
    files, names, total = {}, set(), 0

    def accept(name, size, mode, directory, reader):
        nonlocal total
        name = safe_name(name)
        if name in names:
            raise ValueError('duplicate archive path: ' + repr(name))
        names.add(name)
        if len(names) > MAX_ENTRIES:
            raise ValueError('archive entry limit exceeded')
        if directory:
            return
        if not name:
            raise ValueError('empty file name')
        if size < 0 or size > MAX_FILE or total + size > MAX_TOTAL:
            raise ValueError('archive size limit exceeded')
        total += size
        with reader() as stream:
            data = stream.read(size + 1)
        if len(data) != size:
            raise ValueError('archive entry size mismatch')
        files[name] = (data, mode)

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > MAX_ENTRIES:
                raise ValueError('archive entry limit exceeded')
            for item in archive.infolist():
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError('links and special archive entries are unsupported')
                accept(item.filename, item.file_size, mode, item.is_dir(), lambda: archive.open(item))
    else:
        with tarfile.open(path, mode='r|*') as archive:
            for item in archive:
                if not (item.isfile() or item.isdir()):
                    raise ValueError('links and special archive entries are unsupported')
                accept(item.name, item.size, item.mode, item.isdir(), lambda: archive.extractfile(item))
    return files
