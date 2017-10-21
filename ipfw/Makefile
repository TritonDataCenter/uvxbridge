.include "../Makefile.inc"
.include <bsd.init.mk>

.PATH: ${.CURDIR}/../kipfw/extra
CFLAGS += -include ../kipfw/extra/glue.h
CFLAGS += $(INCDIR)
SRCS= ipfw2.c dummynet.c main.c ipv6.c altq.c tables.c glue.c opt_ipsec.h

LDFLAGS += -lutil # expand_number and humanize_number
CFLAGS += $(INCDIRS)
CFLAGS += -DUSERSPACE	# communicate through userspace

LIB=ipfw

.include <bsd.lib.mk>
opt_ipsec.h:
	(cd ../objs; $(MAKE) -f ../kipfw/Makefile include_e)

#$(OBJS) : ipfw2.h ../extra/glue.h ../$(OBJDIR)/include_e
