
This tool removes a signature from a kernel module file, as created by
the kernel tool [scripts/sign-file.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/sign-file.c).

This tool exists because a common way of removing such signature is
by using strip(1), but that also alters the module in other ways.

It currently only handles the most common variant of module signing.
