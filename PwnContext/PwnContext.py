from pwn import *
import roputils
from pwnlib.context import _validator, _Tls_DictStack, _defaultdict
import os
from os.path import realpath  #because of some problems when using symbolic link

#-----extra function------#
def pad(size, content = '', alnum = False):
    ''' compatibility for autopwn, generate rubbish pad'''
    return content.ljust(size, 'a')

class Map(object):
    def __init__(self, start, end, perm, mapname):
        self.start = start
        self.end = end
        self.perm = perm
        self.mapname = mapname
    def __repr__():
        return 'Map({}, {}, {}, {})'.format(mapname, hex(start), hex(end), perm)
def vmmap(pid):
    # this code is converted from vmmap of peda
    maps = []
    mpath = "/proc/%s/maps" % pid
    #00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
    pattern = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")
    out = open(mpath).read()
    matches = pattern.findall(out)
    if matches:
        for (start, end, perm, mapname) in matches:
            start = int("0x%s" % start, 16)
            end = int("0x%s" % end, 16)
            if mapname == "":
                mapname = "mapped"
            maps.append(Map(start, end, perm, mapname)) # this is output format
    return maps
def check_alive(pid, name = ''):
    CHECK_ALIVE = "ps -q {} -o comm= "
    r = os.popen(CHECK_ALIVE.format(pid))
    p_n = r.read()
    if name:
        if p_n == name: return True
        else: return False
    else:
        if p_n:return True
        else:return False
        

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
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

#wrappers
def _io():
    def _io_wrapper(func):
        '''
        decorator for io
        '''
        name = func.__name__
        doc = func.__doc__
        def wrapper(*args, **kargs):
            if ctx.io_sleep: sleep(ctx.io_sleep)
            return func(*args, **kargs)
        return wrapper
    return _io_wrapper

def _process():
    def _process_wrapper(func):
        '''
        decorator for process
        '''
        name = func.__name__
        doc = func.__doc__
        def wrapper(self, *args, **kargs):
            if not isinstance(self.io, process):
                log.failure("self.io is not a process. failed to use <{}>".format(name))
                return None
            if not self.io.connected():
                log.failure("self.io(process) has been closed. failed to use <{}>".format(name))
                return None
            
            return func(self, *args, **kargs)

        return wrapper
    return _process_wrapper
            
def _log(log_level = 'info'):
    def _log_wrapper(func):
        ''' don't show log '''
        name = func.__name__
        doc = func.__doc__
        def wrapper(self, *args, **kargs):
            pre_log_level = context.log_level
            context.log_level = log_level
            ret_val = func(self, *args, **kargs)
            context.log_level = pre_log_level
            return ret_val
        return wrapper
    return _log_wrapper
#-----main code------#
               
class PwnContext(object):
    defaults = {
                'binary':None,
                'libc':None, 
                'io':None,
               }
    def __init__(self, binary = '', libc = '', io_sleep = 0):
        ''' assign binary and libc at first or later , path or ELF supported '''
        self._tls = _Tls_DictStack(_defaultdict(PwnContext.defaults))
        self.binary = binary
        self.libc = libc
        
        self.io_sleep = io_sleep
    def __repr__(self):
        return 'PwnContext(binary = {}, libc = {}, io_sleep = {})'.format(self.binary, self.libc, self.io_sleep)
        
    @_validator
    def binary(self, binary):
        """
        Same as context.binary, but set binary for the PwnContext.
        """
        if not binary: return None
        if not isinstance(binary, ELF):
            if not os.access(binary, os.R_OK): 
                log.failure("Invalid path {} to binary".format(binary))
                return None
            binary = ELF(binary)
        context.binary = binary
        return binary
    @_validator
    def libc(self, libc):
        """
        Similar to context.binary, but set libc for the PwnContext. Set this to None to enable using local libc
        """
        if not libc: return None
        if not isinstance(libc, ELF):
            if not os.access(libc, os.R_OK): 
                log.failure("Invalid path {} to libc".format(libc))
                return None
            libc = ELF(libc)
        return libc
    @_validator
    def io(self, io):
        """
        process or remote
        """
        return io
    @property
    @_process()
    def bases(self):
        '''
        get program, libc, heap, stack bases
        '''
        bases = {'mapped':0,
                 'libc':0,
                 'base':0,
                 'heap':0,
                 'stack':0,}
        maps = vmmap(self.io.pid)
        for m in maps[::-1]:   #search backward to ensure getting the base
            if m.mapname == 'mapped':    
                bases['mapped'] = m.start
            if m.mapname == realpath(self.libc.path):
                bases['libc'] = m.start
            if m.mapname == realpath(self.binary.path):
                bases['base'] = m.start
            if m.mapname == '[stack]':
                bases['stack'] = m.start
            if m.mapname == '[heap]':
                bases['heap'] = m.start
        return bases
    @_process()   
    def leak(self, addr, size=0):
        ''' leak memory when io is process '''
        if size == 0:
            size = context.bytes
        if not isinstance(self.io, process):
            log.failure("Leaking at {} failed. io is not process".format(addr))
            return 0
        return self.io.leak(addr, size)
    
    @_process() 
    def debug(self, gdbscript = '', exe = None, arch = None, ssh = None):
        return attach(self.io, gdbscript, exe, arch, ssh)
    
    @_log('info')
    def start(self, gdbscript = '', remote_addr = None, env = {}, **kwargs):
        ''' 
            auto start a process, 
            if gdbscript assigned then debug at entry, 
            if remote_addr assigned then connect remote server
            priority: remote > debug > process
        '''
        # checking if there is an open io, then close it.
        if self.io:
            self.io.close()
        # libc setting
        if not self.libc:
            progress = log.progress("libc not provided, tring to use default libc".format(remote_addr))
            if self.binary:
                if self.binary.libc:
                    progress.success("Using default libc {}".format(self.binary.libc))
                    self.libc = self.binary.libc
                else: #static
                    progress.failure("Binary is staticly linked")
            else:
                progress.failure("binary not assigned")
                
        if remote_addr:
            self.io = remote(remote_addr[0], remote_addr[1])
            return self.io
        else:
            # checking if assigned binary.
            if not self.binary:
                log.failure("Please assign PwnContext.binary")
                return None

            if self.libc:
                if "LD_PRELOAD" in env:
                    env["LD_PRELOAD"] = "{}:{}".format(env["LD_PRELOAD"], self.libc.path)
                else:
                    env["LD_PRELOAD"] = self.libc.path
                log.info("env={}".format(env))
            # debug at entry or not
            if gdbscript:
                self.io = self.binary.debug(gdbscript = gdbscript, env = env, **kwargs)
            else:
                self.io = self.binary.process(env = env, **kwargs)

        return True
    
    
    def __getattr__(self, attr):
        '''use ctx.io by default'''
        if hasattr(self.io, attr):
            @_io()
            def call(*args, **kwargs):
                return self.io.__getattribute__(attr)(*args, **kwargs)
            return call
    


ctx = PwnContext()
               


