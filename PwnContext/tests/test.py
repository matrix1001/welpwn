import sys
import os
sys.path.insert(0, os.path.abspath('../../'))
from PwnContext.core import *

TEST_BIN = '/bin/cat'
TEST_LIB = '../libs/libc-2.23/64bit/libc.so.6'
TEST_LIB2 = '../libs/libc-2.25/64bit/libc.so.6'
# Initial test
log.info('Testing basic function')
ctx.binary = ELF(TEST_BIN)
assert type(ctx.binary) == ELF
ctx.binary = ''
ctx.binary = TEST_BIN
assert type(ctx.binary) == ELF

ctx.remote_libc = ELF(TEST_LIB)
assert type(ctx.remote_libc) == ELF
ctx.remote_libc = ''
ctx.remote_libc = TEST_LIB
assert type(ctx.remote_libc) == ELF

# process test
log.info('Testing ctx.io (process)')
ctx.start()
log.info('pid: {}'.format(ctx.pid))
for name in ctx.bases:
    log.info('{}: {:#x}'.format(name, ctx.bases[name]))
log.info('canary: {:#x}'.format(ctx.canary))
log.info('libc path: {}'.format(ctx.libc.path))
ctx.sendline('test')
assert ctx.recv() == 'test\n'

# remote test
log.info('Testing ctx.io (remote)')
p = process('nc -lvp 1234 -e {}'.format(TEST_BIN).split())
ctx.remote = ('localhost', 1234)
ctx.start('remote')
ctx.sendline('test')
assert ctx.recv() == 'test\n'
p.close()

# ld test
log.info('Testing multi glibc support')
ctx.debug_remote_libc = True
ctx.start()
ctx.sendline('test')
assert ctx.recv() == 'test\n'
log.info('libc path: {}'.format(ctx.libc.path))
assert ctx.libc.path == os.path.abspath(TEST_LIB)

ctx.remote_libc = TEST_LIB2
ctx.start()
ctx.sendline('test')
assert ctx.recv() == 'test\n'
log.info('libc path: {}'.format(ctx.libc.path))
assert ctx.libc.path == os.path.abspath(TEST_LIB2)

# gdb utils test
log.info('Testing gdb support')
ctx.symbols = {'sym1': 0x1234, 'sym2': 0x5678}
ctx.breakpoints = [0x1234, 0x5678]
ctx.start()
print('''now i will open a gdb. you have to check the symbols on your own.
if you are in pwndbg, follow these:

p/x $sym1
p/x $sym2
bl

then check those values, they are pre setted in ctx.symbols and ctx.breakpoints

after you finished check. just exit the gdb with `q` .''')
raw_input('press enter to continue.')
ctx.debug(gdbscript='echo test\\n')

# libc_search and one_gadgets test
log.info('Testing libc_search')
result = libc_search({'printf': 0x800, 'puts': 0x690})
assert os.path.basename(result.path) == 'libc6_2.23-0ubuntu10_amd64.so'
log.info('Testing one_gadget')
ones = one_gadgets(TEST_LIB2)
assert ones == [265099, 265183, 890131]
# success
ctx.close()
log.success('test success !')
