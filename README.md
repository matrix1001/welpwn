# Introduction
A pwn framework(based on `pwntools`) aiming at eliminating dull work while scripting and debugging. 

Initially designed for glibc auto loading.

Best performance on `ipython`.



## Features
- excelent context control via `ctx` for the binary and its libc
- symbol management via `sym_ctx`(e.g. define a symbol and you can use it in gdb)
- auxilliary functions for debug(e.g. ctx.bases['libc'] will give you the libc base address)

# Install
You need to install pwntools first.

`python setup.py install`
# Usage
## Template
Template for quick scripting.
```python
from PwnContext import *
#https://github.com/matrix1001/welpwn
if __name__ == '__main__':
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux
    context.log_level = 'debug'
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data))
    st      = lambda delim,data         :ctx.sendthen(str(delim), str(data))
    sl      = lambda data               :ctx.sendline(str(data))
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    slt     = lambda delim,data         :ctx.sendlinethen(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()

    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    def dbg(gdbscript='', *args, **kwargs):
        gdbscript = sym_ctx.gdbscript + gdbscript
        return ctx.debug(gdbscript, *args, **kwargs)

    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

```
## Basic
### Process
Here's a very basic usage demo.
```python
from PwnContext import *
ctx.binary = '/bin/sh'  #auto load the binary
print 'ctx.binary type:',type(ctx.binary)
ctx.start()
print 'ctx.libc type:',type(ctx.libc)    #libc will be automaticly assigned

ctx.sendline('whoami')   #same usage as process('/bin/sh')
print 'recv:', ctx.recv()
```
result:
```
[*] '/bin/sh'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
ctx.binary type: <class 'pwnlib.elf.elf.ELF'>
[x] libc not provided, tring to use default libc
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc not provided, tring to use default libc: Using default libc ELF('/lib/x86_64-linux-gnu/libc.so.6')
[*] env={'LD_PRELOAD': '/lib/x86_64-linux-gnu/libc.so.6'}
[x] Starting local process '/bin/sh'
[+] Starting local process '/bin/sh': pid 25496
ctx.libc type: <class 'pwnlib.elf.elf.ELF'>
recv: root
```
### Remote
Same script can be used to exploit remote target with only a little change.

Run this in the shell before.

`nc -lvp 2333 -c /bin/sh`

Then run this script.
```python
from PwnContext import *
ctx.binary = '/bin/sh'  #auto load the binary
print 'ctx.binary type:',type(ctx.binary)
ctx.start(remote_addr = ('localhost', 2333))  #here's the only change
print 'ctx.libc type:',type(ctx.libc)    #libc will be automaticly assigned

ctx.sendline('whoami')   #same usage as process('/bin/sh')
print 'recv:', ctx.recv()
```
result:
```
[*] '/bin/sh'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
ctx.binary type: <class 'pwnlib.elf.elf.ELF'>
[x] libc not provided, tring to use default libc
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc not provided, tring to use default libc: Using default libc ELF('/lib/x86_64-linux-gnu/libc.so.6')
[x] Opening connection to localhost on port 2333
[x] Opening connection to localhost on port 2333: Trying ::1
[x] Opening connection to localhost on port 2333: Trying 127.0.0.1
[+] Opening connection to localhost on port 2333: Done
ctx.libc type: <class 'pwnlib.elf.elf.ELF'>
recv: root
```

## Advanced
### Vmmap
Here's a demo about how to get all addresses(program base, libc base, heap base ...) in python automatically.
```python
from PwnContext import *
ctx.binary = '/bin/sh'
ctx.start()
print ctx.bases
#if ctx.bases does not fit you harsh demand, try this.
print '\nnow we print a full vmmap\n'
print vmmap(ctx.io.pid)
```
result:
```
......
......
{'libc': 139776500604928, 'base': 93953060052992, 'stack': 140724668264448, 'heap': 93953077415936, 'mapped': 93953062268928}

now we print a full vmmap

[Map("/bin/dash", 0x556232cf5000, 0x556232d10000, "r-xp"),
 Map("/bin/dash", 0x556232f0f000, 0x556232f11000, "r--p"),
 Map("/bin/dash", 0x556232f11000, 0x556232f12000, "rw-p"),
 Map("mapped", 0x556232f12000, 0x556232f14000, "rw-p"),
 Map("[heap]", 0x556234407000, 0x556234428000, "rw-p"),
 Map("/lib/x86_64-linux-gnu/libc-2.25.so", 0x7f4ca8588000, 0x7f4ca8721000, "r-xp"),
 Map("/lib/x86_64-linux-gnu/libc-2.25.so", 0x7f4ca8721000, 0x7f4ca8921000, "---p"),
 Map("/lib/x86_64-linux-gnu/libc-2.25.so", 0x7f4ca8921000, 0x7f4ca8925000, "r--p"),
 Map("/lib/x86_64-linux-gnu/libc-2.25.so", 0x7f4ca8925000, 0x7f4ca8927000, "rw-p"),
 Map("mapped", 0x7f4ca8927000, 0x7f4ca892b000, "rw-p"),
 Map("/lib/x86_64-linux-gnu/ld-2.25.so", 0x7f4ca892b000, 0x7f4ca894e000, "r-xp"),
 Map("mapped", 0x7f4ca8b4b000, 0x7f4ca8b4d000, "rw-p"),
 Map("/lib/x86_64-linux-gnu/ld-2.25.so", 0x7f4ca8b4d000, 0x7f4ca8b4e000, "r--p"),
 Map("/lib/x86_64-linux-gnu/ld-2.25.so", 0x7f4ca8b4e000, 0x7f4ca8b4f000, "rw-p"),
 Map("mapped", 0x7f4ca8b4f000, 0x7f4ca8b50000, "rw-p"),
 Map("[stack]", 0x7fff36a24000, 0x7fff36a45000, "rw-p"),
 Map("[vvar]", 0x7fff36ad0000, 0x7fff36ad3000, "r--p"),
 Map("[vdso]", 0x7fff36ad3000, 0x7fff36ad5000, "r-xp"),
 Map("[vsyscall]", 0xffffffffff600000, 0xffffffffff601000, "r-xp")]

```
### Pre-brute-force
And there's something you may be interested if you have done some challenges about brute force.Let me show you how to do pre-brute-force before exploit(local debug). If you want to brute force heap, you will need to call malloc first.
```python
from PwnContext import *
ctx.binary = '/bin/sh'
while True:
    ctx.start()
    libc_base = ctx.bases['libc']
    if (libc_base & 0xf000) == 0x2000: break
print 'now we got libc base:', hex(ctx.bases['libc'])
```
result:
```
......
[*] env={'LD_PRELOAD': '/lib/x86_64-linux-gnu/libc.so.6'}
[x] Starting local process '/bin/sh'
[+] Starting local process '/bin/sh': pid 21892
[*] Stopped process '/bin/sh' (pid 21892)
......
[*] env={'LD_PRELOAD': '/lib/x86_64-linux-gnu/libc.so.6'}
[x] Starting local process '/bin/sh'
[+] Starting local process '/bin/sh': pid 21895
now we got libc base: 0x7f680e782000
```

### GDB Symbols(basic)
Define symbols for quick use in gdb(ASLR supported). 

ps:There's a much more advanced usage for gdb symbols, c structures can be auto compiled for debugging. Check SymbolContext.py and c_utils.py for detail.
```python
from PwnContext import *
ctx.binary = '/bin/sh'
sym_ctx.symbols = {'testsym':0x12345,}
ctx.start()
print 'gdbscript:', sym_ctx.gdbscript
ctx.debug(sym_ctx.gdbscript)
```
result:
```
......
......
gdbscript: set $testsym=0x55c6ee013345

[*] running in new terminal: /usr/local/bin/gdb -q  "/bin/dash" 26496 -x "/tmp/pwnIdY7re.gdb"
[x] Waiting for debugger
[+] Waiting for debugger: Done
```
then check this in gdb:
```
pwndbg> p/x $testsym
$1 = 0x55c6ee013345
```
## Auxiliary
### auto change interpreter
solve pwn challenges with different libc.(you need to compile various version of libc first)
```python
from PwnContext import *
#move ld.so(choose the proper version) to cwd, then
e = change_ld('/bin/sh', './ld-2.26.so') #return value is ELF
```
output:
```
[*] '/bin/sh'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
[+] PT_INTERP has changed from /lib64/ld-linux-x86-64.so.2 to ./ld-2.26.so. Using temp file /tmp/pwn/sh_debug
[*] '/tmp/pwn/sh_debug'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```
after this, you can use LD_PRELOAD to load the same version of libc.

full example:
```python
from PwnContext import *
ctx.binary = change_ld('/bin/sh', './ld-2.26.so')
ctx.libc = './libc-2.26.so'
ctx.start()
print vmmap(ctx.io.pid) #now we have loaded a libc-2.26 which is different from system libc.
```
result:
```
......
[......
 ......
 Map("/tmp/pwn/libc-2.26.so", 0x7f883edc7000, 0x7f883ef6e000, "r-xp"),
 Map("/tmp/pwn/libc-2.26.so", 0x7f883ef6e000, 0x7f883f16d000, "---p"),
 Map("/tmp/pwn/libc-2.26.so", 0x7f883f16d000, 0x7f883f171000, "r--p"),
 Map("/tmp/pwn/libc-2.26.so", 0x7f883f171000, 0x7f883f173000, "rw-p"),
 ......
 ......]

```
!!caution!!!

Because of LD_PRELOAD, you may find problems when calling execve or system, but this doesn't affect exploiting remote target.
### one_gadget
one_gadget support(you have to install one_gadget first)
```python
from PwnContext import *
print one_gadgets('/lib/x86_64-linux-gnu/libc.so.6')
print 'now we run it again.it will use cache to speed up'
print one_gadgets('/lib/x86_64-linux-gnu/libc.so.6')
```
result:
```
[+] dump one_gadgets from /lib/x86_64-linux-gnu/libc.so.6 : [265195, 265279, 891189]
[265195, 265279, 891189]
now we run it again.it will use cache to speed up
[+] using cached gadgets /root/.one_gadgets/7fb8b29b6dafb0ffe252eba2b54c5781bc6f3e99
[265195, 265279, 891189]
```
### libc-database
libc-database support(you have to clone libc-database first, then change LIBCDB_PATH in auxiliary.py)

if more than one libc found, there will be a ui to ask you for choice(check code for detail).
```python
from PwnContext import *
print libc_search({'printf':0x6b0})
```
result:
```
ELF('/root/Desktop/libc-database/db/libc6_2.19-0ubuntu6_amd64.so')
```
### instruction_log
this is a wrapper to log method. it's usefull to track your code, especially when there's something wrong.
```python
from PwnContext import *
@instruction_log()
def test_function(*args, **kwargs):
    print 'from method:',args, kwargs

test_function('test', 1, 2, 3, a=1)
test_function('test2', b=0)
```
result:
```
[*] 6:test_function('test', 1, 2, 3, a=1)
from method: ('test', 1, 2, 3) {'a': 1}
[*] 7:test_function('test2', b=0)
from method: ('test2',) {'b': 0}
```
now you must have noticed that instruction_log shows your code and its line number.if you still don't understand this, check `example/babyheap`.
## More
read the code!
# Documention
TODO
# Update Log
## 2018/5/25 Version 0.7.1
- update README
- add libc-database support
- add instruction_log (check example babyheap for usage end result)
## 2018/5/22 Version 0.7
- move some auxiliary functions in PwnContext.py to auxiliary.py
- add one_gadget supported
- add runable example (babyheap)
