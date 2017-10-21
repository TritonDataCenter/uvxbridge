# gnu Makefile to build a userland version of the 
# kernel code for ipfw+dummynet
#
# The kernel code is compiled with appropriate flags to make
# it see a kernel-like environment.
# The userland emulation code is compiler with regular flags.

# M is the current directory, used in recursive builds
# so we allow it to be overridden
.include "../Makefile.inc"
.include <bsd.init.mk>

PATHS= extra sys/netpfil/ipfw sys/netinet sys/net 
.PATH: ${PATHS:M*:S/^/${.CURDIR}\//g} 

OBJPATH = $(M)/../$(OBJDIR)

NETMAP_FLAGS = -DWITH_NETMAP -I$(NETMAP_INC)

INCDIRS = -I$(M)/../$(OBJDIR)/include_e -DEMULATE_SYSCTL
INCDIRS += -I$(M)/sys -I$(M)/extra/sys -I$(M)/extra/sys/contrib/pf

E_CFLAGS += $(INCDIRS)
E_CFLAGS += -include $(M)/../kipfw/extra/glue.h		# headers
E_CFLAGS += -include $(M)/../kipfw/extra/missing.h		# headers
E_CFLAGS += -O2 -Wall -Werror
E_CFLAGS += -fno-strict-aliasing
#E_CFLAGS += -pedantic # gcc 4.8.x has problems
E_CFLAGS += -std=gnu99
#E_CFLAGS += -Wno-gnu-empty-struct -Wno-zero-length-array
#E_CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
E_CFLAGS += -Wno-variadic-macros
E_CFLAGS += -Wno-pointer-arith

E_CFLAGS += -g
E_CFLAGS += -DKERNEL_SIDE	# build the kernel side of the firewall
E_CFLAGS += -DUSERSPACE	# communicate through userspace
E_CFLAGS += $(EFLAGS) $(NETMAP_FLAGS)
E_CFLAGS += . -DINET
E_CFLAGS += -DIPFIREWALL_DEFAULT_TO_ACCEPT
E_CFLAGS += -D_BSD_SOURCE 
E_CFLAGS += -D_DEFAULT_SOURCE # on glibc 2.20 and above
# many of the kernel headers need _KERNEL
E_CFLAGS += -D_KERNEL
E_CFLAGS += $(CFLAGS2)

#ipfw + dummynet section, other parts are not compiled in
SRCS_IPFW	 = ip_fw2.c ip_fw_pfil.c ip_fw_sockopt.c
SRCS_IPFW	+= ip_fw_dynamic.c ip_fw_log.c
SRCS_IPFW	+= ip_dummynet.c ip_dn_io.c ip_dn_glue.c
SRCS_IPFW	+= ip_fw_iface.c ip_fw_table.c ip_fw_table_algo.c ip_fw_table_value.c
SRCS_IPFW	+= dn_heap.c
SRCS_IPFW	+= dn_sched_fifo.c dn_sched_wf2q.c
SRCS_IPFW	+= dn_sched_rr.c dn_sched_qfq.c
SRCS_IPFW	+= dn_sched_prio.c
SRCS_NET	 = radix.c
SRCS_NETINET	 = in_cksum.c
# Module glue and functions missing in linux
IPFW_SRCS	= $(SRCS_IPFW) $(SRCS_NET) $(SRCS_NETINET)
IPFW_SRCS += ipfw2_mod.c # bsd_compat.c

IPFW_SRCS += missing.c netmap_io.c
#session.c 
IPFW_CFLAGS= -DINET

E_CFLAGS += -Dradix -DNEED_ROUNDUP2


CFLAGS = $(E_CFLAGS)
SRCS=$(IPFW_SRCS)
LIB=kipfw

all: include_e 

#entries to create empty files
EFILES+= opt_inet.h opt_ipsec.h opt_ipdivert.h \
	 opt_inet6.h opt_ipfw.h opt_mpath.h \
	 opt_mbuf_stress_test.h opt_param.h \
	 timeconv.h

EFILES += altq/if_altq.h vm/vm.h vm/vm_extern.h \
	netpfil/pf/pf_mtag.h netinet6/ip6_var.h \
	machine/cpufunc.h

EFILES_net	+= if_var.h route.h if_clone.h
EFILES_netinet	+= in_var.h ip_var.h udp_var.h
EFILES_sys	= proc.h sockopt.h sysctl.h \
		mutex.h _mutex.h _rwlock.h rwlock.h \
		eventhandler.h jail.h ktr.h rmlock.h \
		counter.h 

EFILES += ${EFILES_sys:M*:S/^/sys\//g}
EFILES += ${EFILES_net:M*:S/^/net\//g}
EFILES += ${EFILES_netinet:M*:S/^/netinet\//g}


EDIRS= altq net netinet netinet6 netpfil/pf sys vm machine

include_e:
	-@echo "Building $(OBJPATH)/include_e ..."
	-$(HIDE) rm -rf $(OBJPATH)/include_e opt_*
	-$(HIDE) mkdir -p $(OBJPATH)/include_e
	-$(HIDE) (cd $(OBJPATH)/include_e; mkdir -p $(EDIRS); touch $(EFILES) )


$(IPFW_OBJS) : ../kipfw/extra/glue.h

ip_fw2.o ip_dummynet.o: # EFLAGS= -include missing.h

radix.o:#	CFLAGS += -U_KERNEL

# session.o:	CFLAGS = -O2
nm_util.o:	CFLAGS = -O2 -Wall -Werror $(NETMAP_FLAGS)


#clean:
#	-rm -f *.o $(DN) $(MOD) $(OBJDIR)/*.o
#	-rm -rf include_e
.include <bsd.lib.mk>
