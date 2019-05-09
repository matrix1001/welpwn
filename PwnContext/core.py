import os
import shutil
import re
from functools import wraps
from os.path import realpath
from os.path import abspath

# these three does something to construct the PwnContext
from pwnlib.context import _validator
from pwnlib.context import _Tls_DictStack
from pwnlib.context import _defaultdict

from pwn import *
# implemented in proc.py
from proc import Proc

# two important functions
from utils.misc import libc_search, one_gadgets
"""This core script of `PwnContext` has been changed since 2018/11/6, as a result of a sky
size big bro telling me that the usage of the script is awful.
"""


class BetterDict(object):
    """Just a dict that support a.b <==> a[b]

    Note:
        I didn't add normal dict methods into this class. Use BetterDict._dict directly.
    """
    def __init__(self, _dict):
        self._dict = _dict

    def __repr__(self):
        return str(self._dict)

    def __str__(self):
        return str(self._dict)

    def __getitem__(self, key):
        return self._dict[key]

    def __iter__(self):
        for key in self._dict:
            yield key

    def __getattr__(self, key):
        if key in self._dict:
            return self._dict[key]


def process_only(method):
    """just a wrapper to make sure PwnContext.io is an instance of `process` and alive.
    """
    name = method.__name__

    @wraps(method)
    def wrapper(self, *args, **kargs):
        if not isinstance(self.io, process):
            log.failure('Not a process for {}'.format(name))
            return None
        pid = self.io.pid
        if not os.access('/proc/{}'.format(pid), os.F_OK):
            log.error('process not alive for {}'.format(name))
            return None
        ret_val = method(self, *args, **kargs)
        return ret_val
    return wrapper


class PwnContext(object):
    """PwnContext is designed for accelerating pwnning by automate many dull jobs.

    Examples:
        >>> ctx = PwnContext()
        >>> ctx.binary = '/bin/sh'
        >>> ctx.remote_libc = './libc.so.6'
        >>> ctx.remote = ('localhost', 1234)
    """
    defaults = {
                'binary': None,
                'io': None,
                'proc': None,
                'remote': None,
                'remote_libc': None,
                'debug_remote_libc': False,
                'auto_patch_env': True,
                'custom_lib_dir': None,
                'symbols': {},
                'breakpoints': [],
               }

    def __init__(self, **kwargs):
        self._tls = _Tls_DictStack(_defaultdict(PwnContext.defaults))
        self.update(kwargs)

    @_validator
    def binary(self, binary):
        """ELF: Binary assigned to the PwnContext.

        Args:
            binary (str of ELF): Path to binary of ELF object.
        """
        if not binary:
            return None
        if not isinstance(binary, ELF):
            if not os.access(binary, os.R_OK):
                log.failure("Invalid path {} to binary".format(binary))
                return None
            binary = ELF(binary)
        context.binary = binary
        return binary

    @_validator
    def remote(self, remote_addr):
        """tuple(ip, port): Remote address.
        """
        if type(remote_addr) not in [list, tuple] \
            or len(remote_addr) != 2 \
            or type(remote_addr[0]) != str \
            or type(remote_addr[1]) != int:
            raise TypeError("Need an address like ('localhost', 1234)")
        return remote_addr

    @_validator
    def remote_libc(self, libc):
        """ELF: Remote libc assigned to the PwnContext.
        """
        if not libc:
            return None
        if not isinstance(libc, ELF):
            if not os.access(libc, os.R_OK):
                log.failure("Invalid path {} to libc".format(libc))
                return None
            libc = ELF(libc)
        """bug fix(2018/11/11)
        when the libc name is strange, `Proc` cannot find it.
        """
        LIBC_REGEX = '^[^\0]*libc(?:-[\d\.]+)?\.so(?:\.6)?$'
        if not re.match(LIBC_REGEX, libc.path):
            log.error('Please change the libc name from {} to {}'.format(
                os.path.basename(libc.path),
                "libc.so | libc.so.6 | libc-2.23.so"
            ))
        return libc

    @_validator
    def debug_remote_libc(self, value):
        """bool: True for load process with remote_libc.
        """
        if type(value) != bool:
            raise TypeError("Only support `True` or `False`")
        return value

    @_validator
    def auto_patch_env(self, value):
        """bool: True for patch_environ after loaded remote libc.
        """
        if type(value) != bool:
            raise TypeError("Only support `True` or `False`")
        return value

    @_validator
    def custom_lib_dir(self, value):
        """str : Path to the custom lib dir.
        """
        if type(value) != str:
            raise TypeError("A str of path is needed")
        ld_path_32 = os.path.join(value, "ld-linux.so.2")
        ld_path_64 = os.path.join(value, "ld-linux-x86-64.so.2")
        if not os.access(ld_path_32, os.F_OK) and not os.access(ld_path_64, os.F_OK):
            raise ValueError("Make sure ld-linux.so.2 or ld-linux-x86-64.so.2 is in.")
        return value

    @_validator
    def io(self, io):
        """process or remote: IO assigned to the PwnContext.

        Note:
            Generated by PwnContext.start
        """
        if not isinstance(io, process) and not isinstance(io, remote):
            log.failure("Invalid io {}".format(io))
            return None
        return io

    @_validator
    def symbols(self, symbols):
        """dict: Symbols to set for gdb. e.g. {'buf':0x202010, }

        Note:
            Only support program (PIE) resolve for now.
        """
        if not symbols:
            return {}
        assert type(symbols) == dict
        return symbols

    @_validator
    def breakpoints(self, breakpoints):
        """list: List of breakpoints.

        Note:
            Only support program (PIE) resolve for now.
        """
        if not breakpoints:
            return []
        assert type(breakpoints) == list
        return breakpoints

    @property
    def libc(self):
        """ELF: Dynamically find libc. If io is process, return its real libc.
        if is remote, return remote_libc.
        """
        if isinstance(self.io, remote):
            return self.remote_libc
        elif isinstance(self.io, process):
            return ELF(self.proc.libc)

    @property
    @process_only
    def proc(self):
        """Proc: Implemented in PwnContext/proc.py
        """
        return Proc(self.pid)

    @property
    @process_only
    def bases(self):
        """dict: Dict of vmmap names and its start address.
        """
        proc = self.proc
        return BetterDict(proc.bases)

    @property
    @process_only
    def canary(self):
        """int: Canary value of the process.
        """
        return self.proc.canary

    @property
    @process_only
    def pid(self):
        """int: pid of the process.
        """
        return self.io.pid

    def start(self, method='process', **kwargs):
        """Core method of PwnContext. Handles glibc loading, process/remote generating.

        Args:
            method (str): 'process' will launch a process instance, 'remote' will
            launch a remote instance and 'gdb' will launch process in debug mode.
            **kwargs: arguments to pass to process, remote, or gdb.debug.
        """
        # checking if there is an open io, then close it.
        if self.io:
            self.io.close()

        if method == 'remote':
            if not self.remote:
                log.error("PwnContext.remote not assigned")
            self.io = remote(self.remote[0], self.remote[1])
            return self.io
        else:
            binary = self.binary
            if not binary:
                log.error("PwnContext.binary not assigned")

            # debug remote libc. be aware that this will use a temp binary
            if self.debug_remote_libc:
                env = {}
                # set LD_PRELOAD
                path = self.remote_libc.path
                if 'env' in kwargs:
                    env = kwargs['env']
                if "LD_PRELOAD" in env and path not in env["LD_PRELOAD"]:
                    env["LD_PRELOAD"] = "{}:{}".format(env["LD_PRELOAD"], path)
                else:
                    env["LD_PRELOAD"] = path
                # log.info("set env={} for debugging remote libc".format(env))

                # codes followed change the ld
                cur_dir = os.path.dirname(os.path.realpath(__file__))
                libc_version = get_libc_version(path)
                arch = ''
                if self.binary.arch == 'amd64':
                    arch = '64'
                elif self.binary.arch == 'i386':
                    arch = '32'
                else:
                    log.error('non supported arch')

                if self.custom_lib_dir:
                    # use custom lib. (ld.so, and others)
                    lib_dir = self.custom_lib_dir
                    if arch == '32':
                        ld_path = os.path.join(lib_dir, "ld-linux.so.2")
                    elif arch == '64':
                        ld_path = os.path.join(lib_dir, "ld-linux-x86-64.so.2")
                    if not os.access(ld_path, os.F_OK):
                        raise ValueError("ld.so not founded in the lib dir. May be wrong arch.")
                else:
                    # default lib dir
                    lib_dir = "{}/libs/libc-{}/{}bit/".format(cur_dir, libc_version, arch)
                    ld_path = os.path.join(lib_dir, "ld.so.2")

                # change the ld for the binary
                shutil.copy(ld_path, '/tmp/ld.so.2')
                binary = change_ld(binary, '/tmp/ld.so.2')

                # change the privilege of ld.so.2 (bug fix in 2018/11/8)
                os.chmod('/tmp/ld.so.2', 0b111000000)

                # set LD_LIBRARY_PATH
                """Why set LD_LIBRARY_PATH ?
                It's for a future feature. Simply use LD_PRELOAD and change the ld can
                solve many pwn challenges. But there are some challenges not only require
                libc.so.6, but also need libpthread.so......(and other libs).
                I will add all those libs into `PwnContext/libs` to fix this problem.
                """
                if "LD_LIBRARY_PATH" in env and lib_dir not in env["LD_LIBRARY_PATH"]:
                    env["LD_LIBRARY_PATH"] = "{}:{}".format(env["LD_LIBRARY_PATH"], lib_dir)
                else:
                    env["LD_LIBRARY_PATH"] = lib_dir

                log.info("set env={} for debugging remote libc".format(env))
                kwargs['env'] = env

            if method == 'gdb':
                self.io = binary.debug(**kwargs)
            elif method == 'process':
                self.io = binary.process(**kwargs)
            else:
                log.error('invalid method {}'.format(method))

            if self.auto_patch_env:
                self.patch_environ()

            return self.io

    @property
    @process_only
    def gdbscript(self):
        symbols = self.symbols
        breakpoints = self.breakpoints
        result = ''
        prog_base = 0
        libc_base = self.bases.libc
        heap_base = self.bases.heap
        if self.binary.pie:
            prog_base = self.bases.prog
        for key in symbols:
            if key.startswith('libc_'):
                result += 'set ${}={:#x}\n'.format(key, symbols[key] + libc_base)
            elif key.startswith('heap_'):
                result += 'set ${}={:#x}\n'.format(key, symbols[key] + heap_base)
            else:
                result += 'set ${}={:#x}\n'.format(key, symbols[key] + prog_base)
        for bp in breakpoints:
            result += 'b *{:#x}\n'.format(bp + prog_base)
        return result

    @process_only
    def debug(self, **kwargs):
        """Debug the io if io is an process. Core is to generate gdbscript

        Args:
            **kwargs: args pass to gdb.attach.
        TODO:
            * Add support for heap symbols, libc symbols.
        """
        gdbscript = self.gdbscript
        if gdbscript != '':
            if 'gdbscript' in kwargs:
                gdbscript += '\n' + kwargs['gdbscript']
            kwargs['gdbscript'] = gdbscript
            log.info('Add gdbscript:\n{}'.format(gdbscript))
        return gdb.attach(self.io, **kwargs)

    @process_only
    def patch_environ(self):
        """Fix the trouble raised by change_ld. :P

        Returns:
            bool: True if modified. False if not found.
        """
        founded = False
        p = self.proc
        result = p.search_in_stack('LD_PRELOAD=') + p.search_in_stack('LD_LIBRARY_PATH=')
        for addr, _ in result:
            p.write(addr, '\0')
            founded = True
        return founded

    def update(self, *args, **kwargs):
        """
        Convenience function, which is shorthand for setting multiple
        variables at once.

        Args:
          kwargs: Variables to be assigned in the environment.
        """
        for arg in args:
            self.update(**arg)

        for k,v in kwargs.items():
            setattr(self,k,v)

    def local(self, function=None, **kwargs):
        """local(**kwargs) -> context manager
        Create a context manager for use with the ``with`` statement.
        For more information, see the example below or PEP 343.

        Note:
            This function is converted from `pwntools`.
        Args:
          **kwargs: Variables to be assigned in the new environment.
        Returns:
          ContextType manager for managing the old and new environment.
        Examples:
            >>> ctx.remote = ('localhost', 1234)
            True
            >>> print ctx.remote
            ('localhost', 1234)
            >>> with ctx.local(remote = ('192.168.0.1', 2234)):
            ...     print print ctx.remote
            ('192.168.0.1', 2234)
            >>> print ctx.remote
            ('localhost', 1234)
        """
        class LocalContext(object):
            def __enter__(a):
                self._tls.push()
                self.update(**{k:v for k,v in kwargs.items() if v is not None})
                return self

            def __exit__(a, *b, **c):
                self._tls.pop()

            def __call__(self, function, *a, **kw):
                @functools.wraps(function)
                def inner(*a, **kw):
                    with self:
                        return function(*a, **kw)
                return inner

        return LocalContext()
    def __getattr__(self, attr):
        """This is just a wrapper of ctx.io (process or remote)"""
        if hasattr(self.io, attr):
            method = getattr(self.io, attr)
            if type(method) == 'instancemethod':
                @wraps(method)
                def call(*args, **kwargs):
                    return method(*args, **kwargs)
                return call
            else:
                return method


ctx = PwnContext()


def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK):
        log.failure("Invalid path {} to ld".format(ld))
        return None

    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK):
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)

    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK):
                os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK):
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)
            os.chmod(path, 0b111000000)  # rwx------
    log.success("PT_INTERP has changed from {} to {}. Using temp file {}".format(
        data, ld, path))
    return ELF(path)


def get_libc_version(path):
    """Get the libc version.

    Args:
        path (str): Path to the libc.
    Returns:
        str: Libc version. Like '2.29', '2.26' ...
    """
    content = open(path).read()
    pattern = "libc[- ]([0-9]+\.[0-9]+)"
    result = re.findall(pattern, content)
    if result:
        return result[0]
    else:
        return ""
