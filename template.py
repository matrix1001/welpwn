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