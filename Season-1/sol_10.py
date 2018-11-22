#!/usr/bin/env python
from pwn import *
import sys
import z3

context.terminal = ['tmux','splitw','-h']
context.log_level = 'debug'
gdb_bool = True
gdb_bool = False

def solve1():
    s = z3.Solver()
    x,y = z3.BitVecs('x y',32)
    s.add(x <= 1336)
    s.add(y <= 1336)
    s.add(x - y == 1337)
    if s.check() == z3.sat:
        m = s.model()
        _x = m[x].as_long()
        _y = m[y].as_long()
    r.sendlineafter("x: ",str(_x))
    r.sendlineafter("y: ",str(_y))

def solve2():
    s = z3.Solver()
    x,y = z3.BitVecs('x y',32)
    s.add(x > 1)
    s.add(y > 1337)
    s.add(x * y == 1337)
    if s.check() == z3.sat:
        m = s.model()
        _x = m[x].as_long()
        _y = m[y].as_long()
    r.sendline("%d %d" %(_x,_y))

def solve3():
    s = z3.Solver()
    a,b,c,d,e = z3.BitVecs('a b c d e',32)
    s.add(a < b)
    s.add(b < c)
    s.add(c < d)
    s.add(d < e)
    s.add(a+b+c+d+e == a*b*c*d*e)
    print("here")
    if s.check() == z3.sat:
        m = s.model()
        _a = m[a].as_long()
        _b = m[b].as_long()
        _c = m[c].as_long()
        _d = m[d].as_long()
        _e = m[e].as_long()
    print("yeet")
    r.sendline("%d %d %d %d %d"%(_a,_b,_c,_d,_e))



    
def exploit(r):
    solve1()
    solve2()
    solve3()
    r.interactive()
    return


if __name__ == "__main__":
    log.info("For remote %s HOST PORT" % sys.argv[0])
    
    binary_name = "./match_10"        #put binary name here
    e = ELF(binary_name)

    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(binary_name)
        print util.proc.pidof(r)
        gdb_cmd = [
            "b *0x555555554d72",
            "b *0x0000555555554D27",
            "c"


        ]
        if(gdb_bool):
            gdb.attach(r, gdbscript = "\n".join(gdb_cmd))
            #r =gdb.debug(binary_name, gdbscript = "\n".join(gdb_cmd))
        #r = process("./LOLgame", env={"LD_PRELOAD" : "./libc.so.6.remote"})
        #pause()
        exploit(r)

