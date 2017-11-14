sbin_PROGRAMS = icd2

icd2_CFLAGS = -I../support $(ICD_CFLAGS) -Wall -Werror
icd2_LDADD = $(ICD_LIBS) ../support/libicd_log.la

icd2_SOURCES =	icd_args.c \
		icd_context.c \
		icd_pid.c \
		icd_signal.c \
		icd_plugin.c \
		icd_exec.c

MAINTAINERCLEANFILES = Makefile.in
