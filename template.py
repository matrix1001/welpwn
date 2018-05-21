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

    
        
        
    ctx.binary = './opm'
    sym_ctx.structs['role'] = '''
struct role{
    void *(func);
    char *name;
    long long name_len;
    int punches;
};
'''
    sym_ctx.symbols = [
    Symbol('ptr_lst', 0x2020e0, typ=10, ptr_array=True, struct_name='role'),
    Symbol('role_num', 0x202130, typ='raw'),
    Symbol('a_ptr', 0x2020e0, typ='ptr', struct_name='role')
    ]
    
    rs()
    sl('A'); sl('aaaa'); sl('100');
    sl('A'); sl('bbbb'); sl('100');
    sl('A'); sl('cccc'); sl('100');
    sl('A'); sl('dddd'); sl('100');
    sl('A'); sl('eeee'); sl('100');
    dbg()