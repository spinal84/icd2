ICD_API_VERSION = 1:0:0
SUPPORT_CFLAGS = $(ICD_CFLAGS) -Wall -Werror
SUPPORT_LDFLAGS = -version-info $(ICD_API_VERSION) -Wl,--no-undefined

lib_LTLIBRARIES = libicd_log.la libicd_settings.la

libicd_log_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_log_la_LDFLAGS = $(SUPPORT_LDFLAGS)
libicd_log_la_LIBADD = $(ICD_LIBS)
libicd_log_la_SOURCES = icd_log.c

libicd_settings_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_settings_la_LDFLAGS = $(SUPPORT_LDFLAGS)
libicd_settings_la_LIBADD = $(ICD_LIBS) libicd_log.la
libicd_settings_la_SOURCES = \
			icd_settings.c \
			icd_settings_backend.c \
			icd_backend_gconf.c

MAINTAINERCLEANFILES = Makefile.in
