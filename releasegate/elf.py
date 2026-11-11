"""Bounded ELF metadata reader. Never loads or executes inspected binaries."""
import struct


class InvalidELF(ValueError):
    pass


def inspect_elf(data):
    def fail(message):
        raise InvalidELF(message)

    if len(data) < 16 or data[:4] != b'\x7fELF':
        fail('invalid ELF identification')
    cls, endian = data[4:6]
    if cls not in (1, 2) or endian not in (1, 2) or data[6] != 1:
        fail('unsupported ELF class, encoding or version')
    order = '<' if endian == 1 else '>'

    def unpack(fmt, offset):
        size = struct.calcsize(order + fmt)
        if offset < 0 or offset + size > len(data):
            fail('ELF structure extends beyond file')
        return struct.unpack_from(order + fmt, data, offset)

    hdr = unpack('HHIIIIIHHHHHH' if cls == 1 else 'HHIQQQIHHHHHH', 16)
    kind, machine, version, _, phoff, _, _, ehsize, phsize, phnum, *_ = hdr
    expected_header = 52 if cls == 1 else 64
    expected_ph = 32 if cls == 1 else 56
    if version != 1 or ehsize != expected_header or phnum == 65535:
        fail('invalid or unsupported extended ELF header')
    if phnum and phsize != expected_ph:
        fail('invalid program header size')
    segments, dynamics = [], []
    for i in range(phnum):
        ph = unpack('IIIIIIII' if cls == 1 else 'IIQQQQQQ', phoff + i * phsize)
        if cls == 1:
            typ, off, vaddr, _, filesz, memsz, _, _ = ph
        else:
            typ, _, off, vaddr, _, filesz, memsz, _ = ph
        if off + filesz > len(data) or filesz > memsz:
            fail('invalid segment bounds')
        if typ == 1:
            segments.append((vaddr, off, filesz))
        if typ == 2:
            dynamics.append((off, filesz))
    expected_class = {3: 1, 62: 2, 40: 1, 183: 2}.get(machine)
    if expected_class is not None and cls != expected_class:
        fail('unsupported architecture/class combination (including x32 ABI)')
    if len(dynamics) > 1:
        fail('multiple dynamic segments')
    result = {'architecture': {3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'aarch64', 243: 'riscv'}.get(machine, f'elf-machine-{machine}'),
              'bits': 32 if cls == 1 else 64, 'needed': [], 'versions': [], 'type': kind}
    if not dynamics:
        return result
    off, size = dynamics[0]
    step, fmt = (8, 'iI') if cls == 1 else (16, 'qQ')
    if size // step > 100000:
        fail('dynamic entry limit exceeded')
    tags = {}
    for pos in range(off, off + size - step + 1, step):
        tag, value = unpack(fmt, pos)
        if tag == 0:
            break
        tags.setdefault(tag, []).append(value)
    else:
        fail('unterminated dynamic table')

    def one(tag, default=None):
        values = tags.get(tag, [])
        if len(values) > 1:
            fail('duplicate singleton dynamic tag')
        return values[0] if values else default

    def address(addr, length=1):
        for va, offset, size in segments:
            if va <= addr and addr + length <= va + size:
                return offset + addr - va
        fail('dynamic address outside file-backed load segments')

    straddr, strsize = one(5), one(10)
    if straddr is None or strsize is None:
        fail('dynamic string table missing')
    string_start = address(straddr, strsize)

    def string(index):
        if index >= strsize:
            fail('string index out of bounds')
        start = string_start + index
        end = data.find(b'\0', start, min(string_start + strsize, start + 4096))
        if end < 0:
            fail('unterminated string')
        try:
            return data[start:end].decode('utf-8')
        except UnicodeDecodeError:
            fail('non UTF-8 dynamic string')

    result['needed'] = [string(index) for index in tags.get(1, [])]
    veraddr, count = one(0x6ffffffe), one(0x6fffffff, 0)
    if bool(veraddr is not None) != bool(count):
        fail('inconsistent version requirements')
    if count > len(data) // 16:
        fail('excessive version requirement count')
    if count > 10000:
        fail('version requirement limit exceeded')
    for i in range(count):
        pos = address(veraddr, 16)
        version, cnt, file_index, aux, nxt = unpack('HHIII', pos)
        if version != 1 or cnt > len(data) // 16:
            fail('invalid version requirement')
        if len(result['versions']) + cnt > 10000:
            fail('version requirement limit exceeded')
        library = string(file_index)
        auxaddr = veraddr + aux
        for j in range(cnt):
            auxpos = address(auxaddr, 16)
            _, _, _, name, next_aux = unpack('IHHII', auxpos)
            result['versions'].append({'library': library, 'name': string(name)})
            if j < cnt - 1 and next_aux < 16:
                fail('invalid version auxiliary chain')
            auxaddr += next_aux
        if i < count - 1 and nxt < 16:
            fail('invalid version requirement chain')
        veraddr += nxt
    return result
