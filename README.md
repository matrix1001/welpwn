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
    - 2.19, 2.23-2.29
    - both 32bit and 64bit
- Debug enhancement (support `PIE`).
    - symbols
    - breakpoints
- Misc
    - `libc-database`
    - `one_gadget`
- Heap ? Well, no support for heap analysis. But I have a gif for you. [HeapInspect](https://github.com/matrix1001/heapinspect)

# Install

There are two ways for you to use `welpwn`.

## Via Install

`setup.py` has been added since version `0.9.3`. If you do not frequently update `welpwn`, and have no need for teamwork with this tool, this is the recommended way.

```sh
git clone https://github.com/matrix1001/welpwn && cd welpwn && python setup.py install
```

## Via Path

This is recommended for developers and those who need to share their exploit for teamwork.

```sh
git clone https://github.com/matrix1001/welpwn && cd welpwn && python start.py
```

Then you probably get something like this.

```python
# paste these codes into your exp.py
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'/tmp/welpwn')
from PwnContext.core import *
```

# Usage

## Template

I have prepared a template for you.

```sh
python start.py --template
```

Then you get this.

```python
#https://github.com/matrix1001/welpwn
from PwnContext import *

try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

if __name__ == '__main__':        
    # context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
    context.log_level = 'debug'
    # functions for quick script
    s       = lambda data               :ctx.send(str(data))        #in case that data is an int
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
    dbg     = lambda *args, **kwargs    :ctx.debug(*args, **kwargs)
    # misc functions
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    ctx.binary = './pwn'
    ctx.remote_libc = './libc.so'
    ctx.remote = ('1.1.1.1', 1111)
    ctx.debug_remote_libc = False # True for debugging remote libc, false for local.

    rs()
    # rs('remote') # uncomment this for exploiting remote target

    libc = ctx.libc # ELF object of the corresponding libc.

    # ipy() # if you have ipython, you can use this to check variables.
```

## Basic

Let's make a fresh start.

```python
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

Make glibc loading on the fly. Mom will never worry about your glibc.

This feature is designed to handle the challenge that uses different glibc.

If the glibc has a different version from your system's, it will get segfault while loading.

Try this.

```python
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

You may have noticed that there is a `ctx.libc` in the script. Let me explain what it does.

If you are debugging the local binary, `ctx.libc` will return exactly the `ELF` object of the libc which is loaded by the binary. (system libc or remote libc)

If you are exploiting remote target, it will return the `ELF` of `ctx.remote_libc`.

**Note**

`LD_PRELOAD` and `LD_LIBRARY_PATH` are auto patched to ensure `system` is called successfully. This might affect other environmental variables. To disable this patch, you need to set `ctx.auto_patch_env` to `False`.

Check `ctx.patch_env`, `ctx.start` for more detail.

__new feature__

Now support debugging glibc with symbol file. First you must download glibc binary and its symbol file.

However, I've made one for you. [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)

Follow these.

```python
from PwnContext import *

ctx.binary = '/bin/sh'
# download first
ctx.custom_lib_dir = '/path/to/glibc-all-in-one/libs/2.23-0ubuntu3_amd64'
# also available to use `remote_libc`
# ctx.remote_libc = '/path/to/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so'

ctx.debug_remote_libc = True
# now we start. libc.so should be loaded automatically.
ctx.start()

# now we debug.
ctx.debug()
```

Check this.

```
pwndbg> p &main_arena 
$3 = (malloc_state *) 0x7fdb15055b20
pwndbg> vmmap
......
    0x7fdb14c92000     0x7fdb14e52000 r-xp   1c0000 0      /path/to/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6
......
    0x7fdb1505b000     0x7fdb15081000 r-xp    26000 0      /tmp/ld.so.2
......
```

Well, some of you may prefer to debug glibc with source code, then you need to compile glibc on your own. Just use `custom_lib_dir` and enjoy it.

### Pre-brute-force

Still debug again and again with challenges which need brute force ? Try this.

Note that `ctx.bases.heap` is available only after the process called `malloc`.

```python
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

Now support `heap` and `libc` symbols. Just use a name start with `libc_` or `heap_`.

Try this.

```python
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
git clone https://github.com/niklasb/libc-database && cd libc-database && echo `pwd` > ~/.libcdb_path && ./get
```


```python
from PwnContext.core import *
print libc_search({'printf':0x6b0})
```
result:
```
ELF('/tmp/libc-database/db/libc6_2.19-0ubuntu6_amd64.so')
```

# Update Log

## 2019/5/16 Version 0.9.7

- add support for [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)

## 2018/12/10 Version 0.9.6

- add support for custom libs
- add `patch_env`
- add `auto_patch_env`

## 2018/11/26 Version 0.9.5

- add fix for `change_ld`
- add `addr_generator` (in `utils.misc`)

## 2018/11/22 Version 0.9.4

- add template
- add support for libc/heap symbols
 
## 2018/11/13 Version 0.9.3

- add `setup.py`

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
