---
title: "HSCTF 2020: Emojis (misc)"
date: 2020-06-05
categories: [writeup]
tags: [writeups, misc]
---

For this challenge we had to reverse a script written in an odd esolang based entirely on emojis:
[/static/2020/hsctf/Emojis.txt](script.txt)

### Step 1: What Do the Emojis Mean Mason?

This emoji language is described at [https://esolangs.org/wiki/Emoji-gramming](Esolang), called "Emoji-gramming" or "💻". It's a language with 24 registers, addition, subtraction and conditional flow control. First things first, lets convert this hellscape into something more human readable, writing a disassembler (code at end) we produce the following output:

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
021:    SUB    r2      8    (😈♊💖)
022:    MOV    r3     r21   (😊♋🕙)
023:    MOV    r21    r12   (😊🕙🕐)
024:    ADD    r1     r7    (😇♉♏)
025:    SUB    r1     r3    (😈♉♋)
026:    ADD    r0     r11   (😇♈♓)
027:    ADD    r2      4    (😇♊💞)
028:    ADD    r3      2    (😇♋💕)
029:    IFEQ   r3     r5    (😵♋♍)
030:    MOV    r17    IN    (😊🕕🎤)
031:    IFEQ   r4     r9    (😵♌♑)
032:    ADD    r4     r9    (😇♌♑)
033:    ADD    r11     1    (😇♓💜)
034:    SUB    r10     8    (😈♒💖)
035:    ADD    r7     r8    (😇♏♐)
036:    SUB    r5     r6    (😈♍♎)
037:    IFEQ   r10     4    (😵♒💞)
038:    ADD    r6     r8    (😇♎♐)
039:    ADD    r8      8    (😇♐💖)
040:    SUB    r0     r2    (😈♈♊)
041:    SUB    r4     r11   (😈♌♓)
042:    ADD    r2     r2    (😇♊♊)
043:    SUB    r7     r11   (😈♏♓)
044:    IFEQ   r10     0    (😵♒💔)
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
