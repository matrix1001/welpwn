# Introduction

_Pwnning is an art._

**welpwn** is designed to make pwnning an art, freeing you from dozens of meaningless jobs.

## Features

- `libc address`, `heap address`, `program address` (with `PIE`), `canary`. Why gdb ? `welpwn` gives you all.
- support glibc (2.19, 2.23-2.27), both 32bit and 64bit. Why change virtual machine ? `welpwn` handles them all.
- trouble debugging binary without symbols ? especially with `PIE` ? `welpwn` takes care of it.
- still manually use `libc-database` and `one_gadget` ? `welpwn` does those for you.

# Install

Install is no longger needed. If you have installed older version, use `pip uninstall welpwn` to remove it.

We use `welpwn` in this way:

```
welpwn # python start.py

paste following code into your exp.py

import sys
sys.path.insert(0,'***/welpwn')
from PwnContext.core import *

```

# Usage

## Basic

Let's make a fresh start.

```python
>>> import sys
>>> sys.path.insert(0,'***/welpwn')
>>> from PwnContext.core import *
>>> ctx.binary = '/bin/sh'
[*] '/bin/sh'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
>>> ctx.start()
[x] Starting local process '/bin/sh'
[+] Starting local process '/bin/sh': pid 27377
>>> ctx.sendline('whoami')
>>> print(ctx.recv())
root
```

Let's continue with remote target. Run this in the shell at first `nc -lvp 1234 -e /bin/sh`.

```python
>>> ctx.remote = ('localhost', 1234)
>>> ctx.start('remote')
[*] Stopped process '/bin/sh' (pid 27377)
[x] Opening connection to localhost on port 1234
[x] Opening connection to localhost on port 1234: Trying ::1
[x] Opening connection to localhost on port 1234: Trying 127.0.0.1
[+] Opening connection to localhost on port 1234: Done
>>> ctx.sendline('whoami')
>>> print(ctx.recv())
root
```

If you are not comfortable with `ctx`. You can use this.

```python
>>> p = ctx.start()
[*] Closed connection to localhost port 1234
[x] Starting local process '/bin/sh'
[+] Starting local process '/bin/sh': pid 27703
>>> print(type(p))
<class 'pwnlib.tubes.process.process'>
```

So, it seems rather a wraper of `process` and `remote` in pwntools. What's special ?

```python
>>> print(hex(ctx.bases.libc))
0x7fd1b6b5d000
>>> print(hex(ctx.bases.heap))
0x556e998be000
>>> print(hex(ctx.bases.prog))
0x556e99249000
>>> print(hex(ctx.canary))
0xea507930dd6a9800
```

## Advanced

### Pre-brute-force

Still debug again and again with challenges which need brute force ? Try this.

Note that `ctx.bases.heap` if available only after the process called `malloc`.

```python
import sys
sys.path.insert(0,'***/welpwn')
from PwnContext.core import *
ctx.binary = '/bin/sh'
while True:
    ctx.start()
    libc_base = ctx.bases.libc
    if (libc_base & 0xf000) == 0x2000: break
print 'now we got libc base:', hex(ctx.bases.libc)
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

### GDB Symbols

TODO

### Multi glibc

TODO

### one_gadget

Install `one_gadget` at first.

```python
import sys
sys.path.insert(0,'***/welpwn')
from PwnContext.core import *
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

Clone `libc-database` and do this first.

```sh
echo PATH_TO_LIBCDB > ~/.libcdb_path
```

```python
import sys
sys.path.insert(0,'***/welpwn')
from PwnContext.core import *
print libc_search({'printf':0x6b0})
```
result:
```
ELF('***/libc-database/db/libc6_2.19-0ubuntu6_amd64.so')
```

# Update Log 

## 2018/11/6 Version 0.9.0

This will be a release a few days later.

- reconstruct the framework
  
TODO:
- docs
- finish some features
- finish readme

## 2018/9/7 Version 0.8.0

- add experimental offline pwn framework, check PwnContext/offpwn.py
- not well tested, please issue any wanted feature or bug

## 2018/5/25 Version 0.7.1

- update README
- add libc-database support
- add instruction_log (check example babyheap for usage end result)

## 2018/5/22 Version 0.7.0

- move some auxiliary functions in PwnContext.py to auxiliary.py
- add one_gadget supported
- add runable example (babyheap)
