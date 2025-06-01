#!/bin/sh
#
# Use a locally compiled mingw based toolchain to cross-compile
# for windows 64-bit platforms.
#
# Note that the toolchain must have libsodium available somewhere.

DESTDIR=x86_64-w64-mingw32.static-gcc \
    OBJDIR=obj-windows \
    CC=x86_64-w64-mingw32.static-gcc \
    OSNAME=windows \
    make clean

rm -rf x86_64-w64-mingw32.static-gcc
