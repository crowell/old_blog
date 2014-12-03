---
layout: post
title: "hosting a local kernel ctf challenge"
date: 2014-11-24 00:38:42 -0500
comments: true
categories: ctf pwning kernel
---
#CTF exploitable kernel infrastructure
This year, I got the opportunity to write challenges for [CSAW CTF](https://ctf.isis.poly.edu/) again. One of the challenges I wrote, "krackme", was an exploitable loadable kernel module disguised as a simple crackme.

While the challenge itself may not need a blog post, I hope the the infrastructure that I used to provide vms to the teams is helpful in creating similar challenges in the future.

The problem with having kernel exploits in a ctf is that crashing a kernel can have some serious impact on the system, and allowing more than one team access to the instance is therefore not really a possibility.  With userspace programs, it is cheap to just serve up a new instance or a fork of a program on each connection, and userspace exploits have always been a big part of CTF. With kernel exploits, each team needs its own vm, and the ability to reboot their vm in the case of a crash. This has restricted kernel challenges to on-site CTF mostly, and [mncoppola](https://github.com/mncoppola/Linux-Kernel-CTF) has made a great framework for on-site kernel exploit challenges. I wanted to design my challenge to be more similar to the userspace exploit challenges that we all know and love, so my goals were.

 - Spawn new VM on connect.
 - Give each connection a 'fresh' vm (eg. new copy of hard drive).

Luckilly with [qemu](http://wiki.qemu.org/Main_Page) and [buildroot](http://buildroot.uclibc.org/) this is quite easy to do!

#Building the VM
The first step to hosting a kernel exploit challenge is to build your vulnerable VM. I used buildroot to build my kernel with a minimal busybox userland, and a tiny 4.5mb ext2 disk. You can start by downloading the buildroot tools.

```sh
git clone git://git.buildroot.net/buildroot
cd buildroot
make xconfig
```

and you'll be dropped to the buildroot configurator.  If you've ever built a kernel before, this type of configuration screen may seem familiar (except gui instead of curses). Important options are `Target` to select the architecture you wish to build, `Toolchain` To specify your kernel header version, `Kernel` to build a kernel (if you want a custom configuration, you can check out the kernel source and make your own custom config for that, or you could just use the defconfig from buildroot), and `Filesystem Images` to specify what to use as a root filesystem. I picked `ext2`.

![Imgur](http://i.imgur.com/ef4F9bh.png)

Hit save, and then
```sh
make
```
This may take a while as you download the toolchain, kernel source, and build everything. Check `output/images` for your kernel `bzImage` and `rootfs.ext2` filesystem. At this point you now have a minimal kernel with busybox that you can boot with qemu.This is great, but we need some more things, like the vulnerable module, and some way to launch it. By default, the username `root` has not password and you can login with that. Please remember to change the password!

#Building the module.
If you're like me and don't build kernel modules all the time, you probably just steal the kernel module makefile from the first hit on Google for `Kernel module makefile`. This won't work to build against your custom kernel.

I'm going to assume you have your module source that works here, and just provide the makefile. If you need help writing the module, there are better guides than I can give here.
With this makefile, replace the linux version (3.2.64) that I used, with whatever version you use, krackme.ko with whatever your kernel module is called, and the /path/to/buildroot/ with your actual path to buildroot.

```sh
obj-m += krackme.o
all:
    make -C /path/to/buildroot/output/build/linux-3.2.64 M=$(PWD) modules
clean:
    make -C /path/to/buildroot/output/build/linux-3.2.64 M=$(PWD) clean
```

So now you should have a .ko ready to be inserted to your new kernel.

#Setting up the vm.
This magic qemu incantation will give you access to your vm with some networking.

```sh
/usr/bin/qemu-system-x86_64 -kernel bzImage -hda rootfs.ext2 -boot c -m 64M -append "root=/dev/sda rw ip=10.0.2.15:10.0.2.2:10.0.2.2 console=ttyAMA0 console=ttyS0" -serial stdio  -net nic,vlan=0 -net user,vlan=0 -monitor /dev/null -nographic
```
The first thing to do is to log in as `root` and do some setup. Change the password to something random, and get the vm to the state you want.

Busybox's init scripts run `/etc/init.d/rcS`, so you can add additional instructions there. Mine looks like

```sh
#!/bin/sh


# Start all init scripts in /etc/init.d
# executing them in numerical order.
#
for i in /etc/init.d/S??* ;do

     # Ignore dangling symlinks (if any).
     [ ! -f "$i" ] && continue

     case "$i" in
        *.sh)
            # Source shell script for speed.
            (
                trap - INT QUIT TSTP
                set start
                . $i
            )
            ;;
        *)
            # No sh extension, so fork subprocess.
            $i start
            ;;
    esac
done

/root/setup.sh
```

With `/root/setup.sh` looking like

```sh
#!/bin/sh
.
insmod /root/krackme.ko
mknod /dev/krackme c 250 0
chmod 666 /dev/krackme
sysctl -w vm.mmap_min_addr="0"
echo "nameserver 8.8.8.8" > /etc/resolv.conf
```

The nameserver setup is important for networking, and make sure to actually insmod your kernel module. You can transfer the .ko by any means, wget, mount and copy, etc.

Next add a new user, with a password you will provide to the attackers and exit.
Now you should have a frozen good state vm. This launcher script can be used to give every launch a new copy of the vm from this snapshot. Thanks to [acez](http://acez.re) for telling me about redirecting monitor to `/dev/null` to prevent players from dorpping to the qemu monitor.

```sh
#!/bin/bash
MYFS=$(mktemp)
cp rootfs.ext2 $MYFS
/usr/bin/qemu-system-x86_64 -kernel bzImage -hda $MYFS -boot c -m 64M -append "root=/dev/sda rw ip=10.0.2.15:10.0.2.2:10.0.2.2 console=ttyAMA0 console=ttyS0" -serial stdio  -net nic,vlan=0 -net user,vlan=0 -monitor /dev/null -nographic
rm $MYFS
```

So every launch from this script will now create a new copy of the hard disk, and boot from there. Users will not be able to interfere, and with the small amount of memory, the host vm should be able to host quite a few guests at once.

#Launch on connect.
The last step is make the qemu vm launch when users connect to it. The simplest way is to add a new user to the host vm, and make the launch script the login shell. Give the players login access to the host vm with the provided username/password and the credentials to the user account on the guest vm.

So essentially what needs to be done is

```sh
adduser myuser
# follow the prompts
su myuser
cd /home/myuser
cp /path/to/bzImage .
cp /path/to/rootfs.ext2 .
cp /path/to/launcher/script.sh . # script.sh is the launcher script mentioned in the previous section
# add /home/myuser/script.sh to /etc/shells
chsh -s /home/myuser/script.sh myuser
```

and then login with the `myuser` user will spawn the qemu vm!

#Other notes.
See the PPP suggestions for running a ctf [here](https://github.com/pwning/docs/blob/master/suggestions-for-running-a-ctf.markdown) for other tips for a local kernel challenge. While what I've posted here will help you set up the infrastructure, it won't guarantee a good challenge, so following the advice there is an important step! Most importantly, be creative in your challenge, generic challenges are also boring to solve!

Let me know if you have any questions!

```
crowell@shellphish.net
```
