# libkyrka Makefile

CC?=cc
AR?=ar
OBJDIR?=obj
LIB=libkyrka.a
TOPDIR=$(CURDIR)
LIBNYFE=nyfe/.built
PC=$(OBJDIR)/libkyrka.pc
VERSION=$(OBJDIR)/version
SHARED_FLAGS=-shared

EXTRA_LIBS=

DESTDIR?=
PREFIX?=$(DESTDIR)/usr/local
LIB_DIR=$(PREFIX)/lib
PKG_DIR=$(LIB_DIR)/pkgconfig
INCLUDE_DIR=$(PREFIX)/include/libkyrka

RANDOM?=nyfe
KEM?=mlkem1024-ref
CIPHER?=libsodium-aes-gcm
ASYMMETRY?=libsodium-x25519
SIGNATURE?=libsodium-ed25519

KEM_MK_PATH?=$(TOPDIR)/mk/kem/$(KEM).mk
RANDOM_MK_PATH?=$(TOPDIR)/mk/random/$(RANDOM).mk
CIPHER_MK_PATH?=$(TOPDIR)/mk/ciphers/$(CIPHER).mk
ASYMMETRY_MK_PATH?=$(TOPDIR)/mk/asymmetry/$(ASYMMETRY).mk
SIGNATURE_MK_PATH?=$(TOPDIR)/mk/signature/$(SIGNATURE).mk

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
	src/offer.c \
	src/packet.c \
	src/purgatory.c \
	src/vicar.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(COVERAGE)", "1")
	CFLAGS+=-fprofile-arcs -ftest-coverage
endif

ifeq ("$(OSNAME)", "")
OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
endif

ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "darwin")
	SHARED_FLAGS=-dynamiclib -undefined dynamic_lookup -flat_namespace
	CFLAGS+=-DPLATFORM_DARWIN
else ifeq ("$(OSNAME)", "openbsd")
	CFLAGS+=-DPLATFORM_OPENBSD
else ifeq ("$(OSNAME)", "windows")
	CFLAGS+=-DPLATFORM_WINDOWS -DNYFE_PLATFORM_WINDOWS
else ifeq ("$(OSNAME)", "esp32")
	CFLAGS+=-DPLATFORM_ESP32 -DNYFE_PLATFORM_ESP32
else ifeq ("$(OSNAME)", "ios")
	CFLAGS+=-DPLATFORM_IOS -DNYFE_PLATFORM_IOS
endif

all:
	$(MAKE) $(OBJDIR)
	$(MAKE) $(LIB)

include $(KEM_MK_PATH)
include $(CIPHER_MK_PATH)
include $(RANDOM_MK_PATH)
include $(ASYMMETRY_MK_PATH)
include $(SIGNATURE_MK_PATH)

LIBNYFE_OBJS=		nyfe/$(OBJDIR)/sha3.o \
			nyfe/$(OBJDIR)/kmac256.o \
			nyfe/$(OBJDIR)/keccak1600.o \
			nyfe/$(OBJDIR)/agelas.o \
			nyfe/$(OBJDIR)/mem.o \
			nyfe/$(OBJDIR)/random.o \
			nyfe/$(OBJDIR)/passphrase.o \
			nyfe/$(OBJDIR)/file.o \
			nyfe/$(OBJDIR)/utils.o

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

$(LIB): $(LIBNYFE) $(KEMLIB) $(OBJS) $(VERSION).c $(PC)
	$(AR) rcs $(LIB) $(OBJS) $(LIBNYFE_OBJS) $(KEMLIB_OBJS)

$(VERSION).c: force
	@if [ -f RELEASE ]; then \
		printf "const char *kyrka_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION)_gen; \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION)_gen; \
		printf "const char *kyrka_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION)_gen; \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *kyrka_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION)_gen;
	@if [ -f $(VERSION).c ]; then \
		cmp -s $(VERSION)_gen $(VERSION).c; \
		if [ $$? -ne 0 ]; then \
			cp $(VERSION)_gen $(VERSION).c; \
		fi \
	else \
		cp $(VERSION)_gen $(VERSION).c; \
	fi

python-mod:
	$(MAKE) $(OBJDIR)
	$(MAKE) $(OBJDIR)/python/libkyrka.so

$(OBJDIR)/python/libkyrka.so: $(LIB) $(OBJDIR)/python.o
	@mkdir -p $(OBJDIR)/python
	$(CC) $(SHARED_FLAGS) $(OBJDIR)/python.o $(LIB) $(LDFLAGS) -o $@

$(PC): pkgconfig/libkyrka.pc
	sed 's/%%EXTRA_LIBS%%/$(EXTRA_LIBS)/' $< > $@

install:
	$(MAKE)
	mkdir -p $(DESTDIR)$(LIB_DIR)
	mkdir -p $(DESTDIR)$(PKG_DIR)
	mkdir -p $(DESTDIR)$(INCLUDE_DIR)
	install -m 555 $(LIB) $(DESTDIR)$(LIB_DIR)/$(BIN)
	install -m 644 $(PC) $(DESTDIR)/$(PKG_DIR)
	install -m 644 include/libkyrka/* $(DESTDIR)$(INCLUDE_DIR)
	install -m 644 nyfe/include/libnyfe.h $(DESTDIR)$(INCLUDE_DIR)
	install -m 644 nyfe/include/portable_win.h $(DESTDIR)$(INCLUDE_DIR)
	install -m 644 nyfe/include/portable_esp32.h $(DESTDIR)$(INCLUDE_DIR)
	@if [ ! -z "$(CROSS_BUILD)" ]; then \
		rm -f $(LIB); \
	fi

$(LIBNYFE):
	$(MAKE) -C nyfe

src/kyrka.c: $(VERSION).c

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/python.o: src/python.c
	$(eval PYTHONFLAGS=$(shell pkg-config --cflags python3))
	$(CC) $(PYTHONFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

dist:
	./dist-build/host-build.sh
	./dist-build/android-build.sh
	./dist-build/windows-build.sh

dist-clean:
	./dist-build/host-clean.sh
	./dist-build/android-clean.sh
	./dist-build/windows-clean.sh

tests-run:
	env COVERAGE=1 SANITIZE=1 ./dist-build/host-build.sh
	$(MAKE) -C tests
	cd tests && ./obj/test-api
	cd tests && ./obj/test-vicar

clean:
	$(MAKE) -C nyfe clean
	$(MAKE) -C mlkem1024 clean
	rm -rf $(OBJDIR) $(LIB)

.PHONY: all clean force
