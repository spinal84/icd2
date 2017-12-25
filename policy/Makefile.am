lib_LTLIBRARIES = libicd_policy_add.la libicd_policy_merge.la \
		  libicd_policy_one.la libicd_policy_restart.la

POLICY_CFLAGS = -I../icd -I../support $(ICD_CFLAGS) -Wall -Werror
POLICY_LDFLAGS = -Wl,--no-undefined

libicd_policy_add_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_add_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_add_la_LIBADD = $(ICD_LIBS)
libicd_policy_add_la_SOURCES = add.c

libicd_policy_merge_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_merge_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_merge_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_merge_la_SOURCES = merge.c

libicd_policy_one_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_one_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_one_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_one_la_SOURCES = one.c

libicd_policy_restart_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_restart_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_restart_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_restart_la_SOURCES = restart.c

MAINTAINERCLEANFILES = Makefile.in
