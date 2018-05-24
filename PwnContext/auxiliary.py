from pwn import *
import inspect
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
    def __repr__(self):
        return 'Map({}, {}, {}, {})'.format(self.mapname, hex(self.start), hex(self.end), self.perm)
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
    log.success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

LIBCDB_PATH = '/root/Desktop/libc-database'    
def libc_search(query, select=0):
    '''query should be a dick like {'printf':0x6b0, ......}'''
    args = ''
    for name in query:
        args += '{} {} '.format(name, hex(query[name]))
    p = os.popen('{}/find {}'.format(LIBCDB_PATH, args))
    result = p.readlines()
    if len(result)==0:
        log.failure('Unable to find libc with libc-database')
        return None
    if (select==0 and len(result)>1) or select>=len(result):
        select = ui.options('choose a possible libc', result)
    
    libc_path = '{}/db/{}.so'.format(LIBCDB_PATH, result[select].split()[2][:-1])
    return ELF(libc_path)
        
    
def one_gadgets(binary, offset=0):
    if isinstance(binary, ELF):
        binary = binary.path
    if not os.access(binary, os.R_OK):
        log.failure("Invalid path {} to binary".format(binary))
    else:
        r = os.popen("one_gadget -r {}".format(binary))
        data = r.read()
        if data:
            gadgets = [int(_)+offset for _ in data.split()]
            log.success("dump one_gadgets from {} with offset {} :\n\t {}".format(binary, hex(offset), [hex(_) for _ in gadgets]))
            return gadgets
        else:
            log.failure("dump one_gadgets from {} failed".format(binary))
            return []
            
def instruction_log(arg=0):
    def _log_wrapper(func):
        def wrapper(*args, **kargs):
            stack = inspect.stack()
            log.info('{}:{}'.format(stack[1][2], stack[1][4][0]))
            ret_val = func(*args, **kargs)
            return ret_val
        return wrapper
    return _log_wrapper