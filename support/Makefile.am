lib_LTLIBRARIES = libicd_log.la

libicd_log_la_CFLAGS =	$(ICD_CFLAGS) -Wall -Werror
libicd_log_la_LDFLAGS = -Wl,--no-undefined
libicd_log_la_LIBADD = $(ICD_LIBS)

libicd_log_la_SOURCES = icd_log.c

MAINTAINERCLEANFILES = Makefile.in
