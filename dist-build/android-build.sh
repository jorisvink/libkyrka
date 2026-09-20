#!/bin/sh
#
# We use a custom libsodium build on my machines in combination
# with the Android NDK to compile libkyrka.

AR=llvm-ar
CC=aarch64-linux-android28-clang

LIBSODIUM=~/src/libsodium-1.0.20/libsodium-android-armv8-a+crypto/
TOOLCHAIN=~/src/android-ndk-r27c/toolchains/llvm/prebuilt/linux-x86_64/bin

DESTDIR=android-armv8 \
    CROSS_BUILD=1 \
    OBJDIR=obj-android \
    CC=$TOOLCHAIN/$CC \
    LIBSODIUM_PATH=$LIBSODIUM \
    AR=$TOOLCHAIN/$AR \
    make install
