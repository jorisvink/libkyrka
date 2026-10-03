#!/bin/sh

DESTDIR=host-build \
    CROSS_BUILD=1 \
    OBJDIR=obj-host \
    make install
