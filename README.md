# Introduction
A pwn framework aiming at eliminating dull work while scripting and debugging.

If you got any problem, read the code and try to solve it on you own. Then launch an issure if necessary.

## Features
- excelent context control via `ctx` for the binary and its libc
- symbol management via `sym_ctx`(e.g. define a symbol and you can use it in gdb)
- auxilliary functions for debug(e.g. ctx.bases['libc'] will give you the libc base address)

# Install
You need to install pwntools first.

`python setup.py install`
# Usage
## Basic
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
Here's a demo about how to get all addresses(program base, libc base, heap base ...) in python automatically.
```python
from PwnContext import *
ctx.binary = '/bin/sh'
ctx.start()
print ctx.bases
#if ctx.bases does not fit you harsh demand, try this.
print 'now we print a full vmmap'
print vmmap(ctx.io.pid)
```
result:
```
......
......
{'libc': 139776500604928, 'base': 93953060052992, 'stack': 140724668264448, 'heap': 93953077415936, 'mapped': 93953062268928}
now we print a full vmmap
[Map(/bin/dash, 0x559169ba4000, 0x559169bbf000, r-xp),
 Map(/bin/dash, 0x559169dbe000, 0x559169dc0000, r--p),
 Map(/bin/dash, 0x559169dc0000, 0x559169dc1000, rw-p),
 Map(mapped, 0x559169dc1000, 0x559169dc3000, rw-p),
 Map([heap], 0x55916acd4000, 0x55916acf5000, rw-p),
 Map(/lib/x86_64-linux-gnu/libc-2.25.so, 0x7f2f1dd14000, 0x7f2f1dead000, r-xp),
 Map(/lib/x86_64-linux-gnu/libc-2.25.so, 0x7f2f1dead000, 0x7f2f1e0ad000, ---p),
 Map(/lib/x86_64-linux-gnu/libc-2.25.so, 0x7f2f1e0ad000, 0x7f2f1e0b1000, r--p),
 Map(/lib/x86_64-linux-gnu/libc-2.25.so, 0x7f2f1e0b1000, 0x7f2f1e0b3000, rw-p),
 Map(mapped, 0x7f2f1e0b3000, 0x7f2f1e0b7000, rw-p),
 Map(/lib/x86_64-linux-gnu/ld-2.25.so, 0x7f2f1e0b7000, 0x7f2f1e0da000, r-xp),
 Map(mapped, 0x7f2f1e2d7000, 0x7f2f1e2d9000, rw-p),
 Map(/lib/x86_64-linux-gnu/ld-2.25.so, 0x7f2f1e2d9000, 0x7f2f1e2da000, r--p),
 Map(/lib/x86_64-linux-gnu/ld-2.25.so, 0x7f2f1e2da000, 0x7f2f1e2db000, rw-p),
 Map(mapped, 0x7f2f1e2db000, 0x7f2f1e2dc000, rw-p),
 Map([stack], 0x7ffe3eeb7000, 0x7ffe3eed8000, rw-p),
 Map([vvar], 0x7ffe3ef10000, 0x7ffe3ef13000, r--p),
 Map([vdso], 0x7ffe3ef13000, 0x7ffe3ef15000, r-xp),
 Map([vsyscall], 0xffffffffff600000, 0xffffffffff601000, r-xp)]
```
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
## Auxiliary
one_gadget support(you have to install one_gadget first)
```python
from PwnContext import *
print one_gadgets('/lib/x86_64-linux-gnu/libc.so.6')
```
result:
```
[+] dump one_gadgets from /lib/x86_64-linux-gnu/libc.so.6 : [265195, 265279, 891189]
[265195, 265279, 891189]
```
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