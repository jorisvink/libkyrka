#!/bin/sh
#
# Use xcrun compile libkyrka for ios arm64 target.

CC="xcrun -sdk iphoneos clang -arch arm64"

DESTDIR=ios-arm64 \
    OSNAME=ios \
    PREFIX= \
    CROSS_BUILD=1 \
    OBJDIR=obj-iosarm64 \
    CC=$CC \
    make install
