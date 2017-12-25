lib_LTLIBRARIES = libicd_policy_add.la libicd_policy_merge.la \
		  libicd_policy_one.la

SUPPORT_CFLAGS = -I../icd -I../support $(ICD_CFLAGS) -Wall
SUPPORT_LDFLAGS = -Wl,--no-undefined

libicd_policy_add_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_policy_add_la_LDFLAGS = $(SUPPORT_LDFLAGS) -avoid-version
libicd_policy_add_la_LIBADD = $(ICD_LIBS)
libicd_policy_add_la_SOURCES = add.c

libicd_policy_merge_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_policy_merge_la_LDFLAGS = $(SUPPORT_LDFLAGS) -avoid-version
libicd_policy_merge_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_merge_la_SOURCES = merge.c

libicd_policy_one_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_policy_one_la_LDFLAGS = $(SUPPORT_LDFLAGS) -avoid-version
libicd_policy_one_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_one_la_SOURCES = one.c

MAINTAINERCLEANFILES = Makefile.in
