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

__[Detailed Documention](./READMORE.md)__

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

# Template

My personal template for pwn challenge.

```sh
python start.py --template
```

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
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
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

# Core API

`welpwn` is a super wrapper of `pwntools`, using a `ctx` to manage `binary`, `libc`, `gdb` and other stuff.

## `ctx.start`

`ctx.start` support `process`, `remote` and `gdb`.

`process` and `remote` have the same usage as those of `pwntools`.

```
>>> from PwnContext.core import *
>>> ctx.binary = '/bin/sh'
[*] '/bin/sh'
...
>>> ctx.start()
...
[+] Starting local process '/bin/sh': pid 27377
>>> ctx.sendline('whoami')
root
>>> print(ctx.recv())
>>> print('let\'s try remote')
let's try remote
>>> ctx.remote = ('localhost', 1234)
>>> ctx.start('remote')
...
[+] Opening connection to localhost on port 1234: Done
>>> ctx.sendline('whoami')
>>> print(ctx.recv())
root
```

`gdb` is similar to `gdb.debug`. It's convenient to debug at the process entry.

```
>>> ctx.start('gdb', gdbscript='b *0x602010\nc')
...
```

## `ctx.remote_libc`

`ctx.remote_libc` is designed to handle the libc of challenges, which may be different from your system's.

Just assign the path of libc to it, then set `ctx.debug_remote_libc` to `True`.

```python
from PwnContext.core import *
ctx.binary = './pwn'
ctx.remote_libc = './libc.so.6'
ctx.debug_remote_libc = True
ctx.start()
print(ctx.libc.path)
# result: /path/to/current/dir/libc.so.6
```

__Note__

No 100% guarantee for successfully loading the libc. Segfault may happen due to different versions of libc.so and ld.so.

## `ctx.custom_lib_dir`

`ctx.custome_lib_dir` is also designed to handle different libc, especially useful when challenges need other libraries like `libpthread.so`.

```python
from PwnContext.core import *
ctx.binary = './pwn'
ctx.custom_libc_dir = './lib/'
ctx.debug_remote_libc = True
ctx.start()
print(ctx.libc.path)
# result: /path/to/current/dir/lib/libc.so.6
```

__Note__

If you want to debug with symbols, `main_arena` for example, use [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one) to download libc.

If you want to debug with source code, just compile glibc and enjoy it.


## `ctx.bases` and `ctx.canary`

`ctx.bases` gives you start addresses of `prog`, `heap`, `libc`, `stack`.

`ctx.canary` is an integer.

Note that `ctx.bases.heap` is available only after the process called `malloc`.

You can use it to prove your concept and even `pre brute-force`.

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

## `ctx.symbols` and `ctx.breakpoints`

`ctx.symbols` and `ctx.breakpoints` are designed for `gdb`. They both generate gdbscript when you call `ctx.debug()`. Both support `PIE` and `ASLR`.

Check this example.

```python
from PwnContext.core import *

ctx.binary = '/bin/cat'
ctx.symbols = {'sym1':0x1234, 'sym2':0x5678}
ctx.breakpoints = [0x1234, 0x5678]
ctx.start()
ctx.debug()
```

Then the following script is passed to gdb.

```
set $sym2=0x5647464d8678
set $sym1=0x5647464d4234
b *0x5647464d4234
b *0x5647464d8678
```

Use `p/x $sym1` to check it.

Now support `heap` and `libc` symbols. Just use a name starts with `libc_` or `heap_`.