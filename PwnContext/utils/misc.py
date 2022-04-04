from pwn import *
import inspect
import os
import subprocess


def libc_search(query):
    '''Search glibc in libc-database by query.

    Note:
        A ui will show up for you if there are multiple result.
        Somehow ipython has a bug on ui.options. If you use ipython,
        pay attention to this.
    Args:
        query (dict): A dict of symbol names and their addresses. Normally
        one if enough. e.g. {'printf': 0x120, 'write': 0x7fff4263210}.
    Returns:
        ELF: ELF object of found libc.
    '''
    HOME = os.path.expanduser('~')
    RECORD = '{}/.libcdb_path'.format(HOME)
    if not os.access(RECORD, os.F_OK):
        LIBCDB_PATH = raw_input('Please input the absolute libcdb path:')
        f = open(RECORD, 'w')
        f.write(LIBCDB_PATH)
        f.close()
    else:
        LIBCDB_PATH = open(RECORD).read()

    LIBCDB_PATH = LIBCDB_PATH.strip()
    FIND = os.path.join(LIBCDB_PATH, 'find')
    DB = os.path.join(LIBCDB_PATH, 'db')
    args = ''
    for name in query:
        args += '{} {} '.format(name, hex(query[name])[2:])
    p = os.popen('{} {}'.format(FIND, args))
    result = p.readlines()
    if len(result) == 0:
        log.failure('Unable to find libc with libc-database')
        return None
    else:
        fmt = '[?] (libc_search) {} have been found. Choose one.\n'.format(len(result))
        for idx, line in enumerate(result):
            fmt += '    {}) {}'.format(idx, line)
        choice = 0
        while len(result) > 1:
            print(fmt)
            try:
                choice = int(input('Your choice ? '))
                if choice < len(result):
                    break
            except ValueError:
                continue


        libc_name = '{}.so'.format(re.findall(r'\((.*?)\)',result[choice])[0])
        libc_path = os.path.join(DB, libc_name)
        e = ELF(libc_path)
        return e


def one_gadgets(binary, offset=0, use_cache=True):
    '''Automatically search one_gadgets.

    Note:
        There is a bug with older version of one_gadget. Due to update infomation.
        If you meet that bug, just delete ~/.one_gadgets then run this again.
    Args:
        binary (ELF or str): ELF object or path to the binary.
        offset (int, optional): Offset to add to every gadget.
        use_cache (bool, optional): Use cache to speed up during a second search.
    Returns:
        list (int): gadgets with offset (if has).
    '''
    HOME = os.path.expanduser('~')
    ONE_DIR = '{}/.one_gadgets'.format(HOME)
    if isinstance(binary, ELF):
        binary = binary.path
    if not os.access(ONE_DIR, os.F_OK):
        os.mkdir(ONE_DIR)

    if not os.access(binary, os.R_OK):
        log.failure("Invalid path {} to binary".format(binary))
        return []

    sha1 = sha1filehex(binary)
    cache = "{}/{}".format(ONE_DIR, sha1)

    if os.access(cache, os.R_OK) and use_cache:
        log.success("using cached gadgets {}".format(cache))
        with open(cache, 'r') as f:
            gadgets = [int(_) for _ in f.read().split()]
            if offset:
                log.info("add offset {} to gadgets".format(offset))
                gadgets = [_+offset for _ in gadgets]
            return gadgets

    else:
        p = subprocess.Popen(["one_gadget", "-r",  binary], stdout=PIPE, stderr=PIPE)
        ret_code = p.wait()
        st_o, st_e = p.communicate()
        if ret_code == 0:
            if use_cache:
                with open(cache, 'w') as f:
                    f.write(st_o)
            gadgets = [int(_) for _ in st_o.split()]
            log.success("dump one_gadgets from {} : {}".format(binary, gadgets))
            if offset:
                log.info("add offset {} to gadgets".format(offset))
                gadgets = [_+offset for _ in gadgets]
            return gadgets
        else:
            log.failure("dump one_gadgets from {} failed".format(binary))
            log.info("error msg:\n"+st_e)
            return []


def instruction_log(arg=0):
    '''Currently expired. But I got a plan for this one.
    '''
    def _log_wrapper(func):
        def wrapper(*args, **kargs):
            stack = inspect.stack()
            log.info('{}:{}'.format(stack[1][2], stack[1][4][0]))
            ret_val = func(*args, **kargs)
            return ret_val
        return wrapper
    return _log_wrapper

def addr_generator(start_ip, port, count):
    """Generator a list of (ip, port).
    """
    def tostr(ip):
        return '.'.join([str(_) for _ in ip])
    ip = [int(_) for _ in start_ip.split('.')]
    addr_list = [(tostr(ip), port)]
    for i in range(count-1):
        ip[-1] += 1
        addr_list.append((tostr(ip), port))
    return addr_list
