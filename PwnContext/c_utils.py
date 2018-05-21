from pwn import *

C_MAIN = '''
int main(){
return 0;
}
'''
DEFAULT_FILENAME = 'c_struct.c'
DEFAULT_PROGRAM = 'c_struct.o'
def c_compile(source, program):
    if context.arch == 'amd64':
        arch_arg = '-m64'
    elif context.arch == 'i386':
        arch_arg = '-m32'
    cmdline = ["gcc", source, arch_arg, "-g", "-o", program]
    p = process(cmdline)
    p.wait_for_close()
    if p.proc.returncode:
        log.failure(' '.join(cmdline)+ '\n' + p.recv())
        return None
    return program
   
def code_compile(code, filename, program):
    f = open(filename, 'w')
    f.write(code)
    f.close()
    return c_compile(filename, program)
    
def struct_compile(struct_code, filename=DEFAULT_FILENAME, program=DEFAULT_PROGRAM):
    code = struct_code + C_MAIN
    return code_compile(code, filename, program)
    
if __name__ == '__main__':
    code_sample_1 = '''
int a,b,c,d;
const int e=1;
int main(){
    return 0;
}
'''
    code_compile(code_sample_1, 'test.c', 'test.o')
    code_sample_2 = '''
struct man{
    int age;
    char name[20];
    char *addr;
};
struct man a_man, *b_man;
'''
    struct_compile(code_sample_2)










