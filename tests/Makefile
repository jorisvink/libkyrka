# libkyrka tests Makefile

CC?=cc
LIBKYRKA?=../host-build

OBJDIR?=obj
LIB=$(OBJDIR)/libtest.a

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-I$(LIBKYRKA)/include/libkyrka -I../nyfe/include -I.
CFLAGS+=-g

SRC=	framework.c

TESTS=	$(OBJDIR)/test-api
OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)

# XXX ideally should be tied to the mk stuff in libkyrka
# so tests can be run with all type of builds.
LDFLAGS+=	$(LIBKYRKA)/lib/libkyrka.a $(LIB) -lsodium

# XXX library build should be done with sanitizers.
LDFLAGS+=	-fsanitize=address,undefined

all: $(TESTS)

$(LIB): $(OBJS) $(OBJDIR)
	$(AR) rcs $(LIB) $(OBJS)

$(OBJDIR)/test-%: $(LIB) tests/%.c
	$(CC) $(CFLAGS) tests/$*.c $(LDFLAGS) -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(LIB)
	rm -rf $(OBJDIR)

.PHONY: all clean
