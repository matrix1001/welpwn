import re
import os
import six
import codecs
import struct
'''This script is initially designed for my project `HeapInspect`.
https://github.com/matrix1001/heapinspect
'''


def u64(data):
    '''Unpack 64bit data with little endian.

    Args:
        data (str): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<Q', data.ljust(8, '\0'))[0]


def u32(data):
    '''Unpack 32bit data with little endian.

    Args:
        data (str): Data to unpack.
    Return:
        int: Unpacked value.
    '''
    return struct.unpack('<I', data.ljust(4, '\0'))[0]


def get_arch(path):
    '''
    Get the arch of the binary.

    Args:
        path (str): The absolute/relative path to the binary.
    Returns:
        str: the arch of the binary, 32 or 64.
    Raises:
        NotImplememtedError: if the arch is not x86 or x64.
    Examples:
        >>> print(get_arch('/bin/sh'))
        64
        >>> print(get_arch('./a_32bit_bin'))
        32
    '''
    with open(path) as f:
        arch_code = ord(f.read(0x13)[-1])
    x86_mcode = [3, ]  # i386 only
    x64_mcode = [62, ]  # amd64 only
    if arch_code in x86_mcode:
        return '32'
    elif arch_code in x64_mcode:
        return '64'
    else:
        raise NotImplementedError(
            'none supported arch. code {}'.format(arch_code)
            )

LIBC_REGEX = '^[^\0]*libc(?:-[\d\.]+)?\.so(?:\.6)?$'
'''str: The regex to match glibc.

Note:
    The glibc basename should be like libc.so.6, libc-2.23.so, libc.so.
'''


class Map(object):
    '''A class for recording one virtual memory map of a process.

    Attributes:
        start (int): The start position of the map.
        end (int): The end position of the map.
        perm (str): The permission of the map, like r-x, rwx, --x.
        mapname (str): The map name. Usually the path of a binary.
    Args:
        start (int): Start position.
        end (int): End positon.
        perm (str): Permission str.
        mapname (str): Map name.
    '''
    def __init__(self, start, end, perm, mapname):
        self.start = start
        self.end = end
        self.perm = perm
        self.mapname = mapname

    def __repr__(self):
        return 'Map("{}", {}, {}, "{}")'.format(
            self.mapname,
            hex(self.start), hex(self.end),
            self.perm)

    @property
    def range(self):
        '''tuple(int): The range of the map. A tuple of start and end.
        '''
        return (self.start, self.end)

    def isin(self, addr):
        '''Check if the address is in the map.

        Args:
            addr (int): The address to check.
        Returns:
            bool: True if in, false if not in.
        '''
        return addr >= self.start and addr < self.end


def vmmap(pid):
    '''Get the vmmap of a process.

    Note:
        This code is converted from vmmap of peda.
    Args:
        pid (int): The pid of a process.
    Returns:
        list (`Map`): A list of class Map.
    '''

    maps = []
    mpath = "/proc/%s/maps" % pid
    # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
    pattern = re.compile(
        "([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)"
        )
    out = open(mpath).read()
    matches = pattern.findall(out)
    if matches:
        for (start, end, perm, mapname) in matches:
            start = int("0x%s" % start, 16)
            end = int("0x%s" % end, 16)
            if mapname == "":
                mapname = "mapped"
            maps.append(Map(start, end, perm, mapname))
    return maps


class Proc(object):
    '''A Class to handle everything of a process.

    Attributes:
        pid (int): The pid of the process.
        arch (str): The arch of the process.
    Args:
        pid (int): The pid of the process.
    '''
    def __init__(self, pid):
        self.pid = pid
        self.arch = get_arch(self.path)

    @property
    def path(self):
        '''str: The path to the binary of the process.
        '''
        return os.path.realpath("/proc/{}/exe".format(self.pid))

    @property
    def auxv(self):
        '''dict: auxv file parser.
        '''
        content = open('/proc/{}/auxv'.format(self.pid)).read()
        size_t = 0
        unpack = None
        if self.arch == '32':
            size_t = 4
            unpack = u32
        elif self.arch == '64':
            size_t = 8
            unpack = u64
        else:
            raise NotImplementedError('unsupported arch')
        num = len(content) / 2 / size_t
        result = {}
        for i in range(num):
            start = i * 2 * size_t
            key = unpack(content[start: start + size_t])
            val = unpack(content[start + size_t: start + 2 * size_t])
            result[key] = val
        return result

    @property
    def vmmap(self):
        '''list(`Map`): The vmmap of the process.
        '''
        return vmmap(self.pid)

    def _range_merge(self, lst, range_vec):
        merged = 0
        for i, r in enumerate(lst):
            start, end = r
            if start == range_vec[1]:
                lst[i][0] = range_vec[0]
                merged = 1
                break
            elif end == range_vec[0]:
                lst[i][1] = range_vec[1]
                merged = 1
                break
        if not merged:
            lst.append(range_vec)

        return lst

    @property
    def ranges(self):
        '''dict: A dict of the range of maps.

        Examples:
            >>> p = Proc(123)
            >>> print(p.ranges)
            {'mapped': [
                [94107401531392, 94107401613312],
                [140274090311680, 140274090315776]
                ],
             'libc': [[140274092433408, 140274094239744]],
             'prog': [[94107400671232, 94107401531392]],
             'stack': [[140725576220672, 140725576503296]],
             'heap': [[94107411861504, 94107414138880]],
             'libpthread-2.27.so': [[140274092290048, 140274092408832]]}
        '''
        ranges = {
            'mapped': [],
            'libc': [],
            'prog': [],
            'heap': [],
            'stack': [],
            }
        maps = self.vmmap
        for m in maps:
            if m.mapname == 'mapped':
                name = 'mapped'
                ranges[name] = self._range_merge(
                    ranges[name],
                    [m.start, m.end])
            elif re.match(LIBC_REGEX, m.mapname):
                name = 'libc'
                ranges[name] = self._range_merge(
                    ranges[name],
                    [m.start, m.end])
            elif m.mapname == self.path:
                name = 'prog'
                ranges[name] = self._range_merge(
                    ranges[name],
                    [m.start, m.end])
            elif m.mapname == '[stack]':
                name = 'stack'
                ranges[name] = self._range_merge(
                    ranges[name],
                    [m.start, m.end])
            elif m.mapname == '[heap]':
                name = 'heap'
                ranges[name] = self._range_merge(
                    ranges[name],
                    [m.start, m.end])
            else:  # non default ones
                name = os.path.basename(m.mapname)
                if name not in ranges:
                    ranges[name] = [[m.start, m.end], ]
                else:
                    ranges[name] = self._range_merge(
                        ranges[name],
                        [m.start, m.end])
        return ranges

    @property
    def bases(self):
        '''
        dict: Start addresses of the maps.

        Examples:
            >>> p = Proc(123)
            >>> print(p.bases)
            {
                'prog': 94107400671232,
                'stack': 140725576220672,
                'libc': 140274092433408,
                'ld-2.27.so': 140274098434048,
                'heap': 94107411861504,
                'mapped': 94107401531392,
            }
        '''
        bases = {
            'mapped': 0,
            'libc': 0,
            'prog': 0,
            'heap': 0,
            'stack': 0,
            }
        maps = self.vmmap
        for m in maps[::-1]:   # search backward to ensure getting the base
            if m.mapname == 'mapped':
                bases['mapped'] = m.start
            elif re.match(LIBC_REGEX, m.mapname):
                bases['libc'] = m.start
            elif m.mapname == self.path:
                bases['prog'] = m.start
            elif m.mapname == '[stack]':
                bases['stack'] = m.start
            elif m.mapname == '[heap]':
                bases['heap'] = m.start
            else:
                name = os.path.basename(m.mapname)
                bases[name] = m.start
        return bases

    def whereis(self, addr):
        '''Get the map name of the addr.

        Args:
            addr (int): The address to locate.
        Returns:
            str: The map name, '' if not found. Note that
                 libc, prog, stack, heap and mapped are default names
                 and other dynamic libraries will return its basename.
        '''
        for m in self.vmmap:
            if m.isin(addr):
                if m.mapname == 'mapped':
                    return 'mapped'
                if re.match(LIBC_REGEX, m.mapname):
                    return 'libc'
                if m.mapname == self.path:
                    return 'prog'
                if m.mapname == '[stack]':
                    return 'stack'
                if m.mapname == '[heap]':
                    return 'heap'
                return os.path.basename(m.mapname)
        return ''

    def read(self, addr, size):
        '''Read from the memory of the process.

        Args:
            addr (int): The start address.
            size (int): The size to read.
        Returns:
            str: The readed memory. return '' if error.
        '''
        mem = "/proc/{}/mem".format(self.pid)
        f = open(mem)
        f.seek(addr)
        try:
            result = f.read(size)
        except:
            result = ""
            print("error reading: {}:{}".format(hex(addr), hex(size)))
        f.close()
        return result

    def write(self, addr, data):
        '''Write to the memory of the process.

        Args:
            addr (int): The start address.
            data (str or byte): Data to write.
        Returns:
            int: bytes written.
        '''
        mem = "/proc/{}/mem".format(self.pid)
        f = open(mem, 'w')
        f.seek(addr)
        try:
            result = f.write(data)
        except:
            result = 0
            print("error writing: {}:{}".format(hex(addr), hex(size)))
        f.close()
        return result

    def search_in_prog(self, search):
        '''Search in prog.

        Args:
            search (int or str): The content to search.
        Returns:
            list: Search result.
        '''
        return self.searchmem_by_mapname(self.path, search)

    def search_in_libc(self, search):
        '''Search in libc.

        Args:
            search (int or str): The content to search.
        Returns:
            list: Search result.
        '''
        return self.searchmem_by_mapname(self.libc, search)

    def search_in_heap(self, search):
        '''Search in heap.

        Args:
            search (int or str): The content to search.
        Returns:
            list: Search result.
        '''
        return self.searchmem_by_mapname('[heap]', search)

    def search_in_stack(self, search):
        '''Search in stack.

        Args:
            search (int or str): The content to search.
        Returns:
            list: Search result.
        '''
        return self.searchmem_by_mapname('[stack]', search)

    def search_in_all(self, search):
        '''Search in all memory.

        Args:
            search (int or str): The content to search.
        Returns:
            list: Search result.
        '''
        result = []
        ignore_list = ['[vvar]', '[vsyscall]']
        for m in vmmap(self.pid):
            if "r" in m.perm and m.mapname not in ignore_list:
                result += self.searchmem(m.start, m.end, search)
        return result

    def searchmem_by_mapname(self, mapname, search):
        '''Search by mapname.

        Args:
            search (int or str): The content to search.
            mapname (str): The mapname to search.
        Returns:
            list: Search result.
        '''
        result = []
        maps = []
        for m in vmmap(self.pid):
            if m.mapname == mapname:
                maps.append(m)
        for m in maps:
            if "r" in m.perm:
                result += self.searchmem(m.start, m.end, search)

        return result

    def searchmem(self, start, end, search, mem=None):
        '''Memory search.

        Note:
            This function is converted from peda
        Args:
            start (int): Start position.
            end (int): End position.
            search (int or str): The content to search
            mem (:obj:`str`, optional): Memory to search. Default is reading
            from the memory.
        Returns:
            list: Search result.
        Examples:
            >>> p = Proc(123)
            >>> start, end = p.ranges['libc'][0]
            >>> print(p.searchmem(start, end, '/bin/sh'))
            [(140274094003571, '2f62696e2f7368')]
            >>> print(p.searchmem(start, end, '0x9090'))
            [(140274092493384, '9090'),
            (140274092654511, '9090'),
            (140274092654852, '9090'),
            (140274092933110, '9090'),
            (140274093267009, '9090'),
            (140274093598894, '9090'),
            (140274094170352, '9090'),
            (140274094217264, '9090')]
            >>> print(p.searchmem(start, end, 0x1234))
            [(140274092640228, '3412'),
            (140274093007354, '3412'),
            (140274093159881, '3412'),
            (140274094051328, '3412'),
            (140274094056312, '3412'),
            (140274094066740, '3412')]
        '''
        result = []
        if end < start:
            (start, end) = (end, start)
        if mem is None:
            mem = self.read(start, abs(start-end))
        if not mem:
            return result
        if isinstance(search, int):
            search = hex(search)
        if isinstance(search, six.string_types) and search.startswith("0x"):
            # hex number
            search = search[2:]
            if len(search) % 2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
            search = re.escape(search)
        # Convert search to bytes if is not already
        if not isinstance(search, bytes):
            search = search.encode('utf-8')
        try:
            p = re.compile(search)
        except:
            search = re.escape(search)
            p = re.compile(search)
        found = list(p.finditer(mem))
        for m in found:
            index = 1
            if m.start() == m.end() and m.lastindex:
                index = m.lastindex+1
            for i in range(0, index):
                if m.start(i) != m.end(i):
                    result += [
                        (
                            start + m.start(i),
                            codecs.encode(mem[m.start(i): m.end(i)], 'hex')
                        )
                    ]
        return result

    @property
    def libc(self):
        '''str: The path to the glibc of the process.

        Raises:
            Exception: if cannot find the glibc.
        '''
        for m in vmmap(self.pid):
            if re.match(LIBC_REGEX, m.mapname):
                return m.mapname
        raise Exception('cannot find libc path')

    @property
    def canary(self):
        '''int: The canary of the process.
        '''
        random_addr = self.auxv[25]
        size_t = 0
        unpack = None
        if self.arch == '32':
            size_t = 4
            unpack = u32
        elif self.arch == '64':
            size_t = 8
            unpack = u64
        else:
            raise NotImplementedError('unsupported arch')
        data = self.read(random_addr, size_t)
        value = unpack(data) & ~0xff
        return value
