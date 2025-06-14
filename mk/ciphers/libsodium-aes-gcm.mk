#
# AES-GCM support via libsodium in libkyrka.
#

ifeq ("$(LIBSODIUM)", "")
	ifeq ("$(LIBSODIUM_PATH)", "")
		CFLAGS+=$(shell pkg-config libsodium --cflags)
		LDFLAGS+=$(shell pkg-config libsodium --libs)
	else
		CFLAGS+=-I$(LIBSODIUM_PATH)/include
		LDFLAGS+=-L$(LIBSODIUM_PATH)/lib -lsodium
	endif
endif

LIBSODIUM=	1

SRC+=		src/libsodium_aes_gcm.c
