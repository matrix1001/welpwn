# Introduction

_Pwnning is an art._

**welpwn** is designed to make pwnning an art, freeing you from dozens of meaningless jobs.

## Features

- Automatically get those magic values for you.
    - `libc address`
    - `heap address`
    - `stack address`
    - `program address` (with `PIE`)
    - `canary`
- Support multi glibc debugging.
    - 2.19, 2.23-2.27 
    - both 32bit and 64bit
- Debug enhancement (support `PIE`).
    - symbols
    - breakpoints
- Misc
    - `libc-database`
    - `one_gadget`
- Heap ? Well, no support for heap analysis. But I have a gif for you. [HeapInspect](https://github.com/matrix1001/heapinspect)

# Install

Install is no longer needed. If you have installed older version, use `pip uninstall welpwn` to remove it.

We use `welpwn` in this way: ( I use `/tmp` for demo. Don't use that directory :)

```
tmp # pip install pwntools
tmp # git clone https://github.com/matrix1001/welpwn && cd welpwn
welpwn # python start.py

# paste these codes into your exp.py
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
from PwnContext.core import *

```

# Usage

## Basic

Let's make a fresh start.

```python
>>> import sys
>>> sys.path.insert(0,'/tmp/welpwn')
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

So, it seems rather a wrapper of `process` and `remote` in pwntools. What's special ?

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

### Multi glibc support

Make glibc loading on the fly. Mom will never worries about your glibc.

This feature is designed to handle the challenge that uses different glibc.

If the glibc has a different version from your system's, it will get segfault while loading.

Try this.

```python
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
import os
sys.path.insert(0, os.path.abspath('/tmp/welpwn'))
from PwnContext.core import *

# note that my system libc version is 2.27
TEST_BIN = '/bin/cat'
TEST_LIB = '/tmp/welpwn/PwnContext/libs/libc-2.23/64bit/libc.so.6'

ctx.binary = TEST_BIN
ctx.remote_libc = TEST_LIB
ctx.debug_remote_libc = False # this is by default

# use original libc
ctx.start()
print(ctx.libc.path)
# result: /lib/x86_64-linux-gnu/libc-2.27.so
ctx.sendline('test')
assert ctx.recv() == 'test\n' # check if correct

# use original libc
ctx.debug_remote_libc = True
ctx.start()
print(ctx.libc.path)
# result: /tmp/welpwn/PwnContext/libs/libc-2.23/64bit/libc.so.6
ctx.sendline('test')
assert ctx.recv() == 'test\n' # check if correct
```

### Pre-brute-force

Still debug again and again with challenges which need brute force ? Try this.

Note that `ctx.bases.heap` is available only after the process called `malloc`.

```python
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
from PwnContext.core import *
ctx.binary = '/bin/sh'
while True:
    ctx.start()
    libc_base = ctx.bases.libc
    if (libc_base & 0xf000) == 0x2000: break
print 'now we got libc base:', hex(ctx.bases.libc)
# result: now we got libc base: 0x7f680e782000
```

### GDB support

Find it awful to remember those addresses ? Get tired of debugging `PIE` enabled program ?

Try this.

```python
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
from PwnContext.core import *

ctx.binary = '/bin/cat'
ctx.symbols = {'sym1':0x1234, 'sym2':0x5678}
ctx.breakpoints = [0x1234, 0x5678]
ctx.start()
ctx.debug()
```

After the script run `ctx.debug`, `gdb` will show up. (same as `gdb.attach(p)`).

Then check this in gdb.
```
pwndbg> p/x $sym1
$1 = 0x5647464d4234
pwndbg> p/x $sym2
$2 = 0x5647464d8678
pwndbg> bl
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x00005647464d4234
2       breakpoint     keep y   0x00005647464d8678
```

Well, that's because I set `gdbscript` before debug.

This is a sample which gonna save you a great lot time.

```
set $sym2=0x5647464d8678
set $sym1=0x5647464d4234
b *0x5647464d4234
b *0x5647464d8678
```

### Misc

#### one_gadget

Install `one_gadget` at first.
```sh
gem install one_gadget
```

```python
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
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
#### libc-database

Clone `libc-database`.

```sh
git clone https://github.com/niklasb/libc-database
```

Then do this.

```sh
echo PATH_TO_LIBCDB > ~/.libcdb_path
```

```python
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
from PwnContext.core import *
print libc_search({'printf':0x6b0})
```
result:
```
ELF('/tmp/libc-database/db/libc6_2.19-0ubuntu6_amd64.so')
```

# Update Log 

## 2018/11/7 Version 0.9.2

- tests
- readme
- symbols and breakpoints
- pep8
- docs

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
