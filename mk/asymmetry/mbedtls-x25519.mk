#
# x25519 via mbedtls its mbedcrypto lib.
#

ifeq ("$(MBEDTLS)", "")
	CFLAGS+=$(shell pkg-config mbedtls --cflags)
	LDFLAGS+=$(shell pkg-config mbedtls --libs-only-L) -lmbedcrypto
	EXTRA_LIBS+=mbedcrypto
endif

MBEDTLS=	1

SRC+=		$(TOPDIR)/src/mbedtls_x25519.c
