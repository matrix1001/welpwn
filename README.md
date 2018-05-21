# Introduction
A pwn framework aiming at eliminating dull work while scripting and debuging.

If you got any problem, read the code and try to solve it on you own. Then launch an issure if necessary.

## Features
- excelent context control via `ctx` for the binary and its libc
- symbol management via `sym_ctx`(e.g. define a symbol and you can use it in gdb)
- auxilliary functions for debug(e.g. ctx.bases['libc'] will give you the libc base address)

# Install
You need to install pwntools first.

`python setup.py install`
# Usage
At first, you should import PwnContext.
```python
from PwnContext import *
```
- load binary
```python
ctx.binary = './babyheap'
print 'type:',type(ctx.binary)
```
output:
```
[*] '~/pwn/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
type: <class 'pwnlib.elf.elf.ELF'>
```
usage of ctx.binary:`help(ELF)` 
- start process
```python
ctx.start()
```
output:
```
[x] libc not provided, tring to use default libc
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] libc not provided, tring to use default libc: Using default libc ELF('/lib/x86_64-linux-gnu/libc.so.6')
[*] env={'LD_PRELOAD': '/lib/x86_64-linux-gnu/libc.so.6'}
[x] Starting local process '~/pwn/babyheap'
[+] Starting local process '~/pwn/babyheap': pid 9185
[*] Making io by given process of ~/pwn/babyheap
```
libc is automaticly loaded as `ctx.libc` if you did not assign it before.
- connect a remote server
```python
ctx.start(remote_addr = 'localhost', 2333)
```
output:
```
[*] Stopped process '~/pwn/babyheap' (pid 9185)
[x] Opening connection to localhost on port 2333
[x] Opening connection to localhost on port 2333: Trying ::1
[x] Opening connection to localhost on port 2333: Trying 127.0.0.1
[+] Opening connection to localhost on port 2333: Done
[*] Making io by given remote of localhost:2333
```
pay attention that the process launched before will be closed.
- basic IO
```
ctx.start()
print ctx.recv()
ctx.send('1')
```
output:
```
1. Alloc
2. Show
3. Delete
4. Exit
choice:
```
just use ctx as usual. all io commands in pwntools are supported.
- more

read the code!
# Documention
TODO