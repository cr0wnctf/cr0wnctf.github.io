---
title: "HSCTF 2020: Emojis (misc)"
date: 2020-06-05
categories: [writeup]
tags: [writeups, misc]
---

**[TLDR](#tldr)**

For this challenge we had to reverse a script written in an odd esolang based entirely on emojis:
(sds)[/static/2020/hsctf/Emojis.txt](script.txt)

### Step 1: What Do the Emojis Mean Mason?

This emoji language is described at [esolangs](https://esolangs.org/wiki/Emoji-gramming), called "Emoji-gramming" or simply "💻", it's a language with 24 registers, addition, subtraction and conditional flow control. Helpfully, the author of this language has kindly provided an [interpreter](https://pastebin.com/caR1eYJc) we can use to get a feel of things. Lemme just open it up... **Oh god**. It's like magic number soup crossed with an obfuscation tier challenge. Well, we'll just treat that as a reference implementation black box and do our own thing.

First things first, lets convert this emoji script hellscape into something a bit more human readable. Writing a disassembler (code at end) we produce the following output:

```
ADDR    OPCODE LHS    RHS   ORIGINAL
========================================
000:    MOV    r0     IN    (😊♈🎤)
001:    MOV    r1     IN    (😊♉🎤)
002:    MOV    r2     IN    (😊♊🎤)
003:    MOV    r3     IN    (😊♋🎤)
004:    MOV    r4     IN    (😊♌🎤)
005:    MOV    r5     IN    (😊♍🎤)
006:    MOV    r6     IN    (😊♎🎤)
007:    MOV    r7     IN    (😊♏🎤)
008:    MOV    r8     IN    (😊♐🎤)
009:    MOV    r9     IN    (😊♑🎤)
010:    MOV    r10    IN    (😊♒🎤)
011:    MOV    r11    IN    (😊♓🎤)
012:    MOV    r21    IN    (😊🕙🎤)

013:    IFEQ   r1     r21   (😵♉🕙)
014:    SUB    r11    r0    (😈♓♈)
015:    IFEQ   r1     r5    (😵♉♍)
016:    MOV    r2     r7    (😊♊♏)
017:    SUB    r1     r4    (😈♉♌)
018:    ADD    r9     r6    (😇♑♎)
019:    IFEQ   r4     r9    (😵♌♑)
020:    MOV    r12    r3    (😊🕐♋)
021:    SUB    r2     8     (😈♊💖)
022:    MOV    r3     r21   (😊♋🕙)
023:    MOV    r21    r12   (😊🕙🕐)
024:    ADD    r1     r7    (😇♉♏)
025:    SUB    r1     r3    (😈♉♋)
026:    ADD    r0     r11   (😇♈♓)
027:    ADD    r2     4     (😇♊💞)
028:    ADD    r3     2     (😇♋💕)
029:    IFEQ   r3     r5    (😵♋♍)
030:    MOV    r17    IN    (😊🕕🎤)
031:    IFEQ   r4     r9    (😵♌♑)
032:    ADD    r4     r9    (😇♌♑)
033:    ADD    r11    1     (😇♓💜)
034:    SUB    r10    8     (😈♒💖)
035:    ADD    r7     r8    (😇♏♐)
036:    SUB    r5     r6    (😈♍♎)
037:    IFEQ   r10    4     (😵♒💞)
038:    ADD    r6     r8    (😇♎♐)
039:    ADD    r8     8     (😇♐💖)
040:    SUB    r0     r2    (😈♈♊)
041:    SUB    r4     r11   (😈♌♓)
042:    ADD    r2     r2    (😇♊♊)
043:    SUB    r7     r11   (😈♏♓)
044:    IFEQ   r10    0     (😵♒💔)
045:    SUB    r9     r1    (😈♑♉)

046:    MOV    OUT    r0    (😊📢♈)
047:    MOV    OUT    r1    (😊📢♉)
048:    MOV    OUT    r2    (😊📢♊)
049:    MOV    OUT    r3    (😊📢♋)
050:    MOV    OUT    r4    (😊📢♌)
051:    MOV    OUT    r5    (😊📢♍)
052:    MOV    OUT    r6    (😊📢♎)
053:    MOV    OUT    r7    (😊📢♏)
054:    MOV    OUT    r8    (😊📢♐)
055:    MOV    OUT    r9    (😊📢♑)
056:    MOV    OUT    r10   (😊📢♒)
057:    MOV    OUT    r11   (😊📢♓)
058:    MOV    OUT    r21   (😊📢🕙)
```

**Opcodes:**

```
MOV: LHS = RHS
or
MOV: LHS = user_input_character
or
MOV: output RHS

ADD: LHS = LHS + RHS
SUB: LHS = LHS - RHS
IFEQ: if LHS == RHS then skip next line else NOP
```

That makes things a bit clearer. There are 3 phases:

1. Input Flag (12chars)
2. Mess around the flag bytes
3. Output the flag (12chars)

At this point in a regular rev challenge I would reach for angr and let it do it's thing, sadly, that's not possible here... Or is it? My solution: **write a shitty angr clone!**. We can use z3 to symbolically pipe input into the challenge, and track the operations done on them before being output. This is a bit messy to do since we need to branch 128(7 ifs) times and track each state and associated constraints. Then at the end we constrain our symbolic outputs to the given outputs and we can then solve for the flag input! Just like Angr!

An example end state showing how flag characters and tracked and the constraints to reach this state:

```
out[0]  = flag_in[0] + flag_in[11] - (flag_in[2] - 8 + 4)
out[1]  = flag_in[1] - flag_in[4] + flag_in[7] - flag_in[12]
out[2]  = flag_in[2] - 8 + 4 + flag_in[2] - 8 + 4
out[3]  = flag_in[12] + 2
out[4]  = flag_in[4] + flag_in[9] + flag_in[6] - (flag_in[11] + 1)
out[5]  = flag_in[5] - flag_in[6]
out[6]  = flag_in[6]
out[7]  = flag_in[7] + flag_in[8] - (flag_in[11] + 1)
out[8]  = flag_in[8] + 8
out[9]  = flag_in[9] + flag_in[6] - (flag_in[1] - flag_in[4] + flag_in[7] - flag_in[12])
out[10] = flag_in[10] - 8
out[11] = flag_in[11] + 1
```

Constraints, notice how they match the `IFEQ` jumps in the disassembly above:

```
flag_in[1] == flag_in[12]
flag_in[1] == flag_in[5]
flag_in[4] == flag_in[9] + flag_in[6]
flag_in[12] + 2 != flag_in[5]
flag_in[4] != flag_in[9] + flag_in[6]
flag_in[10] - 8 == 4
flag_in[10] - 8 != 0)
```

Excitedly running this new tool we get:

```
➜  emoji git:(master) ✗ python soln.py ./emoji.txt sim
[*] number of output states = 128
[-] Expected output isn't possible :(
```

_HUH?!_ **WHAT??** z3 thinks that there is no possible input that could produce this output. Well that can't be right?

### Haha. Enjoy the broken challenge

Convinced we'd made a mistake in the fancy solve script we went back to basics and worked backwards from the known state to the previous state, eventually finding the flag by luck and force: **FLAG**: `flag{tr3v0r_pAck3r}`

I wonder why we couldn't solve this using z3? Well if we plug this into the black box script from the esolang's wiki **WE GET A DIFFERENT OUTPUT FROM THE CHALLENGE OUTPUT**. THEY GAVE US THE WRONG OUTPUT! THE ONLY WAY TO SOLVE THIS IS TO PARTLY GUESS THE FLAG.

**Actual flag output** = `x@^t¾\x13\xa0}I\x82c4v` ascii:(120, 64, 94, 116, 190, 19, 160, 125, 73, 130, 99, 52, 118)  
_THEIR_ flag output = `xB^r_En}INc4v` ascii:(120, 66, 94, 114, 95, 69, 110, 125, 73, 78, 99, 52, 118)

Well that break trying to solve this via z3. Using the real output our solve script storms it:

```
➜  emoji git:(master) ✗ python soln2.py ./emoji.txt sim
[*] number of states = 128
[*] Got one!
flag_in[0] = t
flag_in[1] = r
flag_in[2] = 3
flag_in[3] = v
flag_in[4] = 0
flag_in[5] = r
flag_in[6] = _
flag_in[7] = p
flag_in[8] = A
flag_in[9] = c
flag_in[10] = k
flag_in[11] = 3
flag_in[12] = r
flag_in[13] = !
```

### TLDR

Broken challenge, the given output is wrong. Use manual spreadsheet techniques to get partway to the flag then guess until the scoreboard says you're right. **sigh**.
