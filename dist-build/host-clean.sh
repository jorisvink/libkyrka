#!/bin/sh

DESTDIR=host-build \
    CROSS_BUILD=1 \
    OBJDIR=obj-host \
    make clean

rm -rf host-build
