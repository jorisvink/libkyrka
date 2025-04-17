# libkyrka Makefile

CC?=cc
OBJDIR?=obj
LIB=libkyrka.a
LIBNYFE=nyfe/libnyfe.a
LIBMLKEM1024=mlkem1024/libmlkem1024.a
VERSION=$(OBJDIR)/version.c

DESTDIR?=
PREFIX?=/usr/local
LIB_DIR=$(PREFIX)/lib
INCLUDE_DIR=$(PREFIX)/include/libkyrka

CIPHER?=openssl-aes-gcm

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude/libkyrka
CFLAGS+=-Inyfe/include
CFLAGS+=-g

SRC=	src/kyrka.c \
	src/cathedral.c \
	src/kdf.c \
	src/key.c \
	src/heaven.c \
	src/mlkem1024.c \
	src/offer.c \
	src/libsodium_aes_gcm.c \
	src/packet.c \
	src/purgatory.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-DPLATFORM_DARWIN
else ifeq ("$(OSNAME)", "openbsd")
	CFLAGS+=-DPLATFORM_OPENBSD
endif

ifeq ("$(LIBSODIUM_PATH)", "")
	CFLAGS+=$(shell pkg-config libsodium --cflags)
else
	CFLAGS+=-I$(LIBSODIUM_PATH)/include
endif


OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

LIBNYFE_OBJS=		nyfe/obj/sha3.o \
			nyfe/obj/kmac256.o \
			nyfe/obj/keccak1600.o \
			nyfe/obj/agelas.o \
			nyfe/obj/mem.o \
			nyfe/obj/random.o \
			nyfe/obj/file.o

LIBMLKEM1024_OBJS=	mlkem1024/obj/cbd.o \
			mlkem1024/obj/fips202.o \
			mlkem1024/obj/indcpa.o \
			mlkem1024/obj/kem.o \
			mlkem1024/obj/ntt.o \
			mlkem1024/obj/poly.o \
			mlkem1024/obj/polyvec.o \
			mlkem1024/obj/reduce.o \
			mlkem1024/obj/symmetric-shake.o \
			mlkem1024/obj/verify.o

all: $(LIB)

$(LIB): $(OBJDIR) $(LIBNYFE) $(LIBMLKEM1024) $(OBJS) $(VERSION)
	$(AR) rcs $(LIB) $(OBJS) $(LIBNYFE_OBJS) $(LIBMLKEM1024_OBJS)

$(VERSION): $(OBJDIR) force
	@if [ -f RELEASE ]; then \
		printf "const char *kyrka_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION); \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		printf "const char *kyrka_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *kyrka_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION);

install:
	mkdir -p $(DESTDIR)$(LIB_DIR)
	mkdir -p $(DESTDIR)$(INCLUDE_DIR)
	install -m 555 $(LIB) $(DESTDIR)$(LIB_DIR)/$(BIN)
	install -m 644 include/libkyrka/* $(DESTDIR)$(INCLUDE_DIR)

$(LIBNYFE):
	$(MAKE) -C nyfe

$(LIBMLKEM1024):
	$(MAKE) -C mlkem1024 tests

src/kyrka.c: $(VERSION)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(MAKE) -C nyfe clean
	$(MAKE) -C mlkem1024 clean
	rm -f $(VERSION)
	rm -rf $(OBJDIR) $(LIB)

.PHONY: all clean force
