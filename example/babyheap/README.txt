the exploit will finnally call execve. 
if your system libc version is 2.23, there will be no problem.
else then you will stuck in gdb because i have changed LD_PRELOAD(env).
so bash will corrupt. but the exploit is ok.
by the way, if you don't use tmux, just comment line 3.