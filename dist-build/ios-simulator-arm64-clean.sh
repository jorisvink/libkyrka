#!/bin/sh
#
# Use xcrun compile libkyrka for ios simulator, arm64 target.

CC="xcrun -sdk iphonesimulator clang -arch arm64"

DESTDIR=ios-simulator-arm64 \
    OSNAME=ios \
    PREFIX= \
    CROSS_BUILD=1 \
    OBJDIR=obj-ios-simulator-arm64 \
    CC=$CC \
    make clean
 
rm -rf ios-simulator-arm64
