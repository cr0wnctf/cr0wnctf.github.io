---
title: "Google CTF Qualifiers 2020: Root Power"
date: 2020-08-25
categories: [writeup]
tags: ["ctf", "rev"]
authors: [nankeen]
---

This weekend, cr0wn competed in [Google CTF 2020](https://ctftime.org/event/1041). We placed 16th, qualifying for the next stage.

We were provided with a virtual machine disk image and had to recover the ___root password___.

## Outline

1. First look at disk image.
2. Access the file system.
3. Discover the authentication mechanism.
4. Reverse engineering a kernel module.
5. Discovering what `initramfs` contains and does.
6. Reverse engineering an AML file.
7. Win.

## TL;DR

The given image has a pluggable authentication module that checks if a char device `/dev/chck` reads __1__ when __root__ login is attempted.
The kernel module responsible for said device reads from ACPI, logic of which is within an ACPI Machine Language (AML) file.
Decompiling it shows that it is a PS/2 keyboard device, and the make/break codes form the flag.

## First look

The archive contains a disk image and a script to run it in QEMU.
GRUB menu reveals that it is Arch Linux, and you are greeted with a login prompt.


![Grub Menu](/images/google20/root-power/qemu-1.png "Grub Menu")
![Login Prompt](/images/google20/root-power/qemu-2.png "Login Prompt")

Binwalk suggests there's an EXT file system at offset `0x100000`.

![Binwalk](/images/google20/root-power/binwalk.png "Binwalk")

## The file system

The file system can be mounted with:

```bash
mkdir -p mnt && sudo mount -o loop,offset=1048576 disk.img mnt
```

My first instinct was to check `/etc/shadow` and the boot files, the former was a rabbit hole.
I also checked `initramfs` to see if there are any files I might have missed, it contains `ssdt.aml`, we'll come back to this later.

## Authentication mechanism
A feature that authenticated users in Linux was PAM.
So I checked out the modules in `/etc/pam.d/system-auth`, and `pam_chck.so` was mentioned.

`pam_chck.so` looks for the __root__ user, then returns 0 (success) if `check_device() == 1`.

```c
ulong pam_sm_authenticate(undefined8 param_1)
{
  int r;
  ulong ret;
  char *user;
  uint _r;
  
  _r = pam_get_user(param_1,&user,"Username: ",&user);
  if (_r == 0) {
    r = strcmp(user,"root");
    if (r == 0) {
      fwrite("Password: ",1,10,stderr);
      r = check_device();
      if (r == 1) {
        fprintf(stderr,"\n\nWelcome %s\n",user);
        ret = 0;
      }
      else {
        fwrite("Wrong username or password",1,0x1a,stderr);
        ret = 6;
      }
    }
    else {
      ret = 6;
    }
  }
  else {
    ret = (ulong)_r;
  }
  return ret;
}
```

`check_device()` is a simple function that reads 2 bytes from `/dev/chck` and returns the result as an integer.

```c
int check_device(void)
{
  int ret;
  char buf [2];
  FILE *fd;
  
  fd = fopen("/dev/chck","r");
  fgets(buf,2,fd);
  fclose(fd);
  ret = atoi(buf);
  return ret;
}
```

What exactly provides this device?


## Chck kernel module

Devices in `/dev/` are usually added through kernel modules, so I looked for `.ko` files in the image.
Immediately, `chck.ko` jumped out so it was given the decompiler treatment, indeed it handles `/dev/chck`.

```c
undefined8 chck_read(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  int chck_r;
  undefined8 r;
  undefined8 extraout_RDX;
  long in_GS_OFFSET;
  undefined8 acpi_data;
  char local_22 [2];
  long canary;
  
  __fentry__();
  canary = *(long *)(in_GS_OFFSET + 0x28);
  chck_r = acpi_evaluate_integer(chck_handle,"CHCK",0,&acpi_data);
  if (chck_r == 0) {
    snprintf(local_22,2,"%llu",acpi_data);
    r = simple_read_from_buffer(param_2,extraout_RDX,param_4,local_22,2);
  }
  else {
    printk("\x014Chck: cannot read from method CHCK");
    r = 0xffffffffffffffff;
  }
  if (canary == *(long *)(in_GS_OFFSET + 0x28)) {
    return r;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}
```

This function relays reads on `/dev/chck` to ACPI's _CHCK_ device.
My guess was that this was handled early in the boot process --- `initramfs`.

## AML file

`initramfs` contains `ssdt.aml` which can be decompiled with `iasl`, producing ssdt.dsl.
The following helped me make sense of what is happening:

1. [https://uefi.org/specifications](https://uefi.org/specifications)
2. [https://wiki.osdev.org/AML](https://wiki.osdev.org/AML)

Here's roughly what it does:

* It defines a device: `CHCK` with 2 operation regions at `SystemIO` addresses `0x60` and `0x64`.
* There's a method, also called `CHCK`, that compares a buffer `KBDB` with `KBDA`, returning 1 if they match and 0 otherwise.
* `KBDB` is populated from `SystemIO:0x60`.
* `KBDA` contained a bunch of pre-defined bytes.

What kind of device is this? Googling ___acpi 0x60 0x64___ yields [this page](https://wiki.osdev.org/%228042%22_PS/2_Controller).
So I made the assumption that `KBDA` contained __PS/2 scan codes__.

That assumption was confirmed with [this table](http://www.vetra.com/scancodes.html).
Each byte represents a make/break code, indicating a key-down/key-up event.

The decode script is trivial and is left as an exercise for the reader.
_Lol kidding_, I did it by hand.

Result was the flag: `CTF{acpi_machine_language}`
