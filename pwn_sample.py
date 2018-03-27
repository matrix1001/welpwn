from PwnContext import *
if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h']  # I always use tmux

    ctx = PwnContext(
                    binary = '', 
                    libc = '', 
                    )
    
    #-----function for quick script-----#
    def sl(tmp):
        return ctx.sendline(tmp)
    def s(tmp):
        return ctx.send(tmp)
    def r(n = 1024):
        return ctx.recv(n)
    def ru(tmp):
        return ctx.recvuntil(tmp)
    def leak(self, addr, size=4):
        return ctx.leak(addr, size)
    def interact():
        return ctx.interactive()
    def dbg(cmd = ''):
        return ctx.debug(cmd)
    def rs(dbg_cmd = '', remote_addr=None):
        return ctx.start(dbg_cmd, remote_addr)