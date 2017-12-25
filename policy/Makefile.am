lib_LTLIBRARIES = libicd_policy_add.la

SUPPORT_CFLAGS = -I../icd $(ICD_CFLAGS) -Wall
SUPPORT_LDFLAGS = -Wl,--no-undefined

libicd_policy_add_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_policy_add_la_LDFLAGS = $(SUPPORT_LDFLAGS) -avoid-version
libicd_policy_add_la_LIBADD = $(ICD_LIBS)
libicd_policy_add_la_SOURCES = add.c

MAINTAINERCLEANFILES = Makefile.in
