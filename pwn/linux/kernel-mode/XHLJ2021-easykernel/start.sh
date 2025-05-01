#!/bin/sh

qemu-system-x86_64  \
-m 64M \
-cpu host,+smep \
-enable-kvm \
-kernel ./bzImage \
-initrd rootfs.img.gz \
-nographic \
-s \
-append "console=ttyS0 kaslr quiet noapic"
