#!/bin/sh
#
# Using the ESP-IDF toolchain compile libkyrka for an esp32s3 target.

AR=xtensa-esp32s3-elf-ar
CC=xtensa-esp32s3-elf-gcc

DESTDIR=esp32s3 \
    OSNAME=esp32 \
    PREFIX= \
    CROSS_BUILD=1 \
    OBJDIR=obj-esp32s3 \
    CC=$CC \
    AR=$AR \
    CFLAGS="-DESP_PLATFORM -D_GNU_SOURCE" \
    make install
