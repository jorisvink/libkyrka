#
# x25519 via libsodium in libkyrka.
#

ifeq ("$(LIBSODIUM)", "")
	ifeq ("$(LIBSODIUM_PATH)", "")
		CFLAGS+=$(shell pkg-config libsodium --cflags)
	else
		CFLAGS+=-I$(LIBSODIUM_PATH)/include
	endif
endif

LIBSODIUM=	1

SRC+=		src/libsodium_x25519.c
