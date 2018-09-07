from pwn import *
from pwnlib.context import Thread
#offline pwn framework


INIT_FAIL = 0
EXP_FAIL = 1
HDL_FAIL = 2

class OffPwn(object):
    def __init__(self):
        self.targets = []
        self.threaded = True
        self.exploit = lambda *args, **kwargs: None
        self.succ_handler = lambda *args, **kwargs: None
        self.fail_handler = lambda *args, **kwargs: None
        self.round_handler = lambda *args, **kwargs: None
        self.log_level = 'info'
        self.interval = 60
        self.wait_thread = False
    
        
    def run(self):
        if self.threaded:
            pool = []
            for target in self.targets:
                thread = Thread(target=self.routine, 
                            args=(target,),
                            )
                pool.append(thread)
            for thread in pool:
                thread.start()
                
            if self.wait_thread:
                for thread in pool:
                    thread.join()
        else:
            for target in self.targets:
                self.routine(target)
                
    def loop(self, times):
        count = 0
        while(count < times):
            count += 1
            self.round_handler(count, times)
            self.run()
            sleep(self.interval)
            
              
    def routine(self, target):
        #init io
        io = self.io_init(target)
        if io == None: 
            self.fail_handler(target, INIT_FAIL)
            return
        #exploit io
        try:
            self.exploit(io)
        except Exception as e:
            self.fail_handler(target, EXP_FAIL)
            return
        io.clean_and_log()
        #handle io
        try:
            self.succ_handler(io)
        except Exception as e:
            self.fail_handler(target, HDL_FAIL)
            return
        
    def io_init(self, target):
        context.log_level = 50
        try:
            io = remote(target[0], target[1])
            context.log_level = self.log_level
            return io
        except Exception as e:
            context.log_level = self.log_level
            return None
    

                
if __name__ == '__main__':
    def exp(io):
        s       = lambda data               :io.send(str(data))        #in case that data is a int
        sa      = lambda delim,data         :io.sendafter(str(delim), str(data), timeout=context.timeout) 
        st      = lambda delim,data         :io.sendthen(str(delim), str(data), timeout=context.timeout) 
        sl      = lambda data               :io.sendline(str(data)) 
        sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data), timeout=context.timeout) 
        slt     = lambda delim,data         :io.sendlinethen(str(delim), str(data), timeout=context.timeout) 
        r       = lambda numb=4096          :io.recv(numb)
        ru      = lambda delims, drop=True  :io.recvuntil(delims, drop, timeout=context.timeout)
        irt     = lambda                    :io.interactive()

        uu32    = lambda data   :u32(data.ljust(4, '\0'))
        uu64    = lambda data   :u64(data.ljust(8, '\0'))
        
        #sl('exit')
        sl('whoami')
        ru('root')
        
    def succ_hdl(io):
        io.sendline('cat /tmp/flag')
        success('%s:%d -> %s', io.rhost, io.rport, io.recv())
    
    fail_lst = []
    def fail_hdl(target, typ):
        if typ == INIT_FAIL:
            log.critical('%s:%d unable to connect', target[0], target[1])
        elif typ == EXP_FAIL:
            log.warn('%s:%d exploit failed', target[0], target[1])
        elif typ == HDL_FAIL:
            log.critical('%s:%d succ_handler failed', target[0], target[1])
        t = (typ, target)
        if t not in fail_lst:
            fail_lst.append(t)
            
    def round_hdl(count, times):
        log.info('==========round %d of %d==========', count, times)
    
    context.timeout = 5
    op = OffPwn()
    op.targets = [
        ('127.0.0.1', 1334),
        ('127.0.0.1', 2334),
        ('127.0.0.1', 3334),
        ('127.0.0.1', 4334),
        ('127.0.0.1', 5334),
        ]
    op.exploit=exp
    op.succ_handler=succ_hdl
    op.fail_handler=fail_hdl
    op.round_handler=round_hdl
    #op.run()
    op.interval = 10
    op.loop(10)
    