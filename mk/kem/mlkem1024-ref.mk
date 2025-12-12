#
# ML-KEM-1024 via the reference implementation carried in libkyrka's repo.
#

KEMLIB_OBJS=	mlkem1024/$(OBJDIR)/cbd.o \
		mlkem1024/$(OBJDIR)/fips202.o \
		mlkem1024/$(OBJDIR)/indcpa.o \
		mlkem1024/$(OBJDIR)/kem.o \
		mlkem1024/$(OBJDIR)/ntt.o \
		mlkem1024/$(OBJDIR)/poly.o \
		mlkem1024/$(OBJDIR)/polyvec.o \
		mlkem1024/$(OBJDIR)/reduce.o \
		mlkem1024/$(OBJDIR)/symmetric-shake.o \
		mlkem1024/$(OBJDIR)/verify.o

KEMLIB=		mlkem1024/$(OBJDIR)/.built

mlkem1024/$(OBJDIR)/.built: $(LIBNYFE)
	$(MAKE) -C mlkem1024
	touch $@

mlkem-tests: $(LIBNYFE)
	$(MAKE) -C mlkem1024 tests

SRC+=		src/mlkem1024_ref.c
