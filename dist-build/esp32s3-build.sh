#!/bin/sh
#
# Using the ESP-IDF toolchain compile libkyrka for an esp32s3 target.

if [ -z "$MBEDTLS_HEADER_PATH" ]; then
	echo "No MBEDTLS_HEADER_PATH set"
	exit 1
fi

if [ -z "$LIBSODIUM_HEADER_PATH" ]; then
	echo "No LIBSODIUM_HEADER_PATH set"
	exit 1
fi

AR=xtensa-esp32s3-elf-ar
CC=xtensa-esp32s3-elf-gcc

INCLUDES="-I$MBEDTLS_HEADER_PATH -I$LIBSODIUM_HEADER_PATH"

DESTDIR=esp32s3 \
    OSNAME=esp32 \
    PREFIX= \
    CROSS_BUILD=1 \
    OBJDIR=obj-esp32s3 \
    KYRKA_NO_INRI_API=1 \
    CC=$CC \
    AR=$AR \
    CFLAGS="-DESP_PLATFORM -D_GNU_SOURCE $INCLUDES" \
    CIPHER=mbedtls-aes-gcm \
    make install
