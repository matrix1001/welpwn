from pwn import *
from pwnlib.context import _validator, _Tls_DictStack, _defaultdict
import os
from os.path import realpath  #because of some problems when using symbolic link

#-----extra function------#
def pad(size, content = '', alnum = False):
    ''' compatibility for autopwn, generate rubbish pad'''
    return content.ljust(size, 'a')
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
            maps += [(start, end, perm, mapname)]  # this is output format
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
def io_alive(instance=None):
    def _io_alive(func):
        '''
        decorator for check io(process/remote) alive
        '''
        name = func.__name__
        doc = func.__doc__
        def wraper(self, *args, **kargs):
            if not self.io:
                log.failure("No io is running when calling <{}>".format(name))
                return None
            if instance and not isinstance(self.io, instance):
                log.failure("io is not {} when calling <{}>".format(instance.__name__, name))
                return None   
            if isinstance(self.io, process):
                if not check_alive(self.io.pid):
                    log.failure("Process io {} has closed when calling <{}>".format(self.io.pid, name))
                    return None
                else: return func(self, *args, **kargs)
            if isinstance(self.io, remote):
                if not self.io.connected():
                    log.failure("Remote io {} has closed when calling <{}>".format(self.io.pid, name))
                    return None
                else: return func(self, *args, **kargs)
            log.failure("io {} is not process, nor remote when calling <{}>".format(self.io, name))
            return None
        return wraper
    return _io_alive
#-----main code------#
class PwnContext(object):
    defaults = {
                'binary':None,
                'libc':None, 
                'ld':None,
                'io':None,
                'io_sleep':0,
               }
    def __init__(self, binary = '', libc = '', ld = ''):
        ''' assign binary and libc at first or later , path and ELF supported '''
        self._tls = _Tls_DictStack(_defaultdict(PwnContext.defaults))
        self.binary = binary
        self.libc = libc
        
    @_validator
    def binary(self, binary):
        """
        Same as context.binary, but set binary for the PwnContext.
        Arch check enable. context.binary set. 
        """
        if not binary: return None
        if not isinstance(binary, ELF):
            if not os.access(binary, os.R_OK): 
                log.failure("Invalid path {} to binary".format(binary))
                return None
            binary = ELF(binary)
        if self.libc:
            if self.libc.arch != binary.arch:
                log.failure("Binary arch {} does not match libc arch {}.Clean libc".format(self.libc.arch, self.binary.arch))
                self.libc = None
                return binary
        context.binary = binary
        return binary
    @_validator
    def libc(self, libc):
        """
        Similar to context.binary, but set libc for the PwnContext. 
        Arch check enable. Set this to None to enable using local libc
        """
        if not libc: return None
        if not isinstance(libc, ELF):
            if not os.access(libc, os.R_OK): 
                log.failure("Invalid path {} to libc".format(libc))
                return None
            libc = ELF(libc)
        if self.binary:
            if libc.arch != self.binary.arch:
                log.failure("Libc arch {} does not match binary arch {}. Using default libc".format(self.libc.arch, self.binary.arch))
                libc = self.binary.libc
        return libc
    @_validator
    def ld(self, ld):
        """
        Force to use assigned ld.so by changing the binary
        """
        if not self.binary:
            log.failure("Binary must be assigned before assign ld")
            return None
        if not ld:
            if self.binary_path:
                info("Reset binary. Set libc to None")
                self.binary = self.binary_path
                self.libc = ''
            return None
        if not os.access(ld, os.R_OK): 
            log.failure("Invalid path {} to ld".format(ld))
            return None
        
        for segment in self.binary.segments:
            if segment.header['p_type'] == 'PT_INTERP':
                size = segment.header['p_memsz']
                addr = segment.header['p_paddr']
                data = segment.data()
                if size <= len(ld):
                    log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                    return None
                self.binary.write(addr, ld.ljust(size, '\0'))
                if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
                for i in range(255):  #here must be care
                    path = '/tmp/pwn/{}_debug_{}'.format(os.path.basename(self.binary.path), i)
                    if not os.access(path, os.F_OK):
                        break
                self.binary.save(path)    
                os.chmod(path, 0b111000000)
        success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
        self.binary = path
        return ld
    @_validator
    def io(self, io):
        """
        process or remote
        """
        if isinstance(io, process):
            info("Making io by given process of {}".format(io.display))
            return io
        if isinstance(io, remote):
            info("Making io by given remote of {}:{}".format(io.rhost, io.rport))
            return io
        
        if type(io)==str:
            # io is the path of the binary
            info("Making io by process('{}'). Be aware that this method cannot set env".format(io))
            io = process(io)
        elif type(io)==tuple or type(io)==list:
            # io is remote addr
            info("Making io by remote('{}',{})".format(io[0], io[1]))
            io = remote(io[0], io[1])
        else:
            log.failure("Wrong io {}".format(str(io)))
            return None
        return io
    @_validator
    def io_sleep(self, io_sleep):
        ''' sleep time (s) before io '''
        if io_sleep < 0:
            log.failure("Wrong io_sleep {}, reset to 0".format(io_sleep))
            io_sleep = 0
        if io_sleep > 10:
            log.warn("io_sleep value {} is to high".format(io_sleep))
        return io_sleep
    
    @property
    @io_alive(process)
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
            if m[3] == 'mapped':    
                    bases.update({'mapped':m[0]})
            if m[3] == realpath(self.libc.path):
                bases.update({'libc':m[0]})
            if m[3] == realpath(self.binary.path):
                bases.update({'base':m[0]})
            if m[3] == '[stack]':
                bases.update({'stack':m[0]})
            if m[3] == '[heap]':
                bases.update({'heap':m[0]})
        return bases
    @io_alive(process)
    def leak(self, addr, size=0):
        ''' leak memory when io is process '''
        if size == 0:
            size = context.bytes
        if not isinstance(self.io, process):
            log.failure("Leaking at {} failed. io is not process".format(addr))
            return 0
        return self.io.leak(addr, size)

    def start(self, dbg_cmd = '', remote_addr = None):
        ''' 
            auto start a process, 
            if dbg_cmd assigned then debug at entry, 
            if remote_addr assigned then connect remote server
        '''
        log_level = context.log_level
        context.log_level = 'info'  #avoid debug log when loading
        # checking if assigned binary.
        if not self.binary:
            log.failure("Please assign PwnContext.binary")
            context.log_level = log_level
            return False
        # checking if there is an open io, close it.
        if self.io:
            self.io.close()
        # start local process or connect to remote addr
        if not remote_addr:
            if self.libc:
                preload = {"LD_PRELOAD":self.libc.path}
            else: 
                preload = {}
                if self.binary.libc:
                    info("Libc not provided, using local libc {}".format(self.binary.libc.path))
                else:
                    info("Binary is staticly linked")
                self.libc = self.binary.libc
            # debug at entry or not
            if dbg_cmd:
                self.io = self.binary.debug(gdbscript = dbg_cmd, env = preload)
            else:
                self.io = self.binary.process(env = preload)
        else:
            self.io = remote_addr
            if not self.libc:
                log.warn("Pwning remote {} without remote libc, using local libc {}".format(remote_addr, self.binary.libc.path))
                self.libc = self.binary.libc
        context.log_level = log_level
        return True
    @io_alive()
    def sendline(self, tmp):
        sleep(self.io_sleep)
        return self.io.sendline(tmp)
    @io_alive()
    def send(self, tmp):
        sleep(self.io_sleep)
        return self.io.send(tmp)
    def recv(self, numb=4096):
        return self.io.recv(numb)
    def recvuntil(self, delims):
        return self.io.recvuntil(delims)
    @io_alive()
    def interactive(self):
        return self.io.interactive()
    @io_alive(process)  
    def debug(self, cmd):
        return attach(self.io, cmd)


        
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux

    ctx = PwnContext(
                    binary = '', 
                    libc = '', 
                    )
    
    #-----function for quick script-----#
    def sl(tmp):
        return ctx.sendline(tmp)
    def s(tmp):
        return ctx.send(tmp)
    def r(n = 1024):
        return ctx.recv(n)
    def ru(tmp):
        return ctx.recvuntil(tmp)
    def leak(self, addr, size=4):
        return ctx.leak(addr, size)
    def interact():
        return ctx.interactive()
    def dbg(cmd = ''):
        return ctx.debug(cmd)
    def rs(dbg_cmd = '', remote_addr=None):
        return ctx.start(dbg_cmd, remote_addr)


