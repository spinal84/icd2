lib_LTLIBRARIES = libicd_log.la libicd_settings.la libicd_dbus.la

SUPPORT_CFLAGS = $(ICD_CFLAGS) -Wall -Werror
SUPPORT_LDFLAGS = -Wl,--no-undefined

libicd_log_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_log_la_LDFLAGS = $(SUPPORT_LDFLAGS) -version-info 1:0:0
libicd_log_la_LIBADD = $(ICD_LIBS)
libicd_log_la_SOURCES = icd_log.c

libicd_settings_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_settings_la_LDFLAGS = $(SUPPORT_LDFLAGS) -version-info 1:0:0
libicd_settings_la_LIBADD = $(ICD_LIBS) libicd_log.la
libicd_settings_la_SOURCES = \
			icd_settings.c \
			icd_settings_backend.c \
			icd_backend_gconf.c

libicd_dbus_la_CFLAGS = $(SUPPORT_CFLAGS)
libicd_dbus_la_LDFLAGS = $(SUPPORT_LDFLAGS) -version-info 2:0:1
libicd_dbus_la_LIBADD = $(ICD_LIBS) libicd_log.la
libicd_dbus_la_SOURCES = icd_dbus.c

MAINTAINERCLEANFILES = Makefile.in
