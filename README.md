# **Essence** — An Operating System

![Screenshot showing the file manager, text editor, and bitmap image editor.](https://nakst.gitlab.io/essence.jpg)

Video demonstration as of October 2021, running on real hardware: (YouTube) 

[![Video demonstration as of October 2021.](http://img.youtube.com/vi/aGxt-tQ5BtM/0.jpg)](http://www.youtube.com/watch?v=aGxt-tQ5BtM "Essence — October ’21 Progress")

## Links

For discussion, join our Discord server: https://discord.gg/skeP9ZGDK8

Alternatively, visit the forums (not very active): https://essence.handmade.network/forums.

To support development, you can donate to my Patreon: https://www.patreon.com/nakst.

## Features

Kernel
* Filesystem independent cache manager.
* Memory manager with shared memory, memory-mapped files and multithreaded paging zeroing and working set balancing.
* Networking stack for TCP/IP.
* Scheduler with multiple priority levels and priority inversion.
* On-demand module loading.
* Virtual filesystem.
* Window manager.
* Audio mixer. (being rewritten)
* Optional POSIX subsystem, capable of running GCC and some Busybox tools.

Applications
* File Manager
* Text Editor
* IRC Client
* System Monitor

Ports
* Bochs
* GCC and Binutils
* FFmpeg
* Mesa (for software-rendered OpenGL)
* Musl

Drivers
* Power management: ACPI with ACPICA.
* Secondary storage: IDE, AHCI and NVMe.
* Graphics: BGA and SVGA.
* Read-write filesystems: EssenceFS.
* Read-only filesystems: Ext2, FAT, NTFS, ISO9660.
* Audio: HD Audio.
* NICs: 8254x.
* USB: XHCI, bulk storage devices, human interface devices.

Desktop
* Custom user interface library.
* Software vector renderer with complex animation support.
* Tabbed windows.
* Multi-lingual text rendering and layout with FreeType and Harfbuzz.

## Building

See `help/Building.md` for a description of how to build and test the system.
