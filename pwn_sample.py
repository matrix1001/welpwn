from PwnContext import *
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux
    context.log_level = 'debug'
    #-----function for quick script-----#
    def sl(*args, **kwargs):
        return ctx.sendline(*args, **kwargs)
    def s(*args, **kwargs):
        return ctx.send(*args, **kwargs)
    def r(*args, **kwargs):
        return ctx.recv(*args, **kwargs)
    def ru(*args, **kwargs):
        return ctx.recvuntil(*args, **kwargs)
    def leak(*args, **kwargs):
        return ctx.leak(*args, **kwargs)
    def interact(*args, **kwargs):
        return ctx.interactive(*args, **kwargs)
    def dbg(*args, **kwargs):
        return ctx.debug(*args, **kwargs)
    def rs(*args, **kwargs):
        return ctx.start(*args, **kwargs)
        
        
    ctx.binary = './pwn'
    ctx.libc = './libc.so.6'
    sym_ctx.symbols = {'name1':0x1234,
                       'name2':0x4567}
    sym_ctx.symbols = Symbol('name3', 0xdeadbeef, 'libc', 12)
    
    rs(env = {'LD_PRELOAD':'./libc.so.6'})
    dbg(sym_ctx.gdbscript+'c')