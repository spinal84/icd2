lib_LTLIBRARIES = libicd_policy_add.la libicd_policy_merge.la \
		  libicd_policy_one.la libicd_policy_restart.la \
		  libicd_policy_ask.la libicd_policy_nw_disconnect.la \
		  libicd_policy_always_online.la libicd_policy_change.la \
		  libicd_policy_any.la

POLICY_CFLAGS = -I../icd -I../support $(ICD_CFLAGS) -Wall -Werror
POLICY_LDFLAGS = -Wl,--no-undefined

libicd_policy_add_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_add_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_add_la_LIBADD = $(ICD_LIBS)
libicd_policy_add_la_SOURCES = policy_add.c

libicd_policy_merge_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_merge_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_merge_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_merge_la_SOURCES = policy_merge.c

libicd_policy_one_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_one_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_one_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_one_la_SOURCES = policy_one.c

libicd_policy_restart_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_restart_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_restart_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_restart_la_SOURCES = policy_iap_restart.c

libicd_policy_ask_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_ask_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_ask_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la \
			      ../support/libicd_dbus.la
libicd_policy_ask_la_SOURCES = policy_iap_ask.c

libicd_policy_nw_disconnect_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_nw_disconnect_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_nw_disconnect_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_nw_disconnect_la_SOURCES = policy_nw_disconnect.c

libicd_policy_always_online_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_always_online_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_always_online_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la \
					../support/libicd_dbus.la
libicd_policy_always_online_la_SOURCES = policy_always_online.c

libicd_policy_change_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_change_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_change_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la \
				 ../support/libicd_dbus.la
libicd_policy_change_la_SOURCES = policy_change.c

libicd_policy_any_la_CFLAGS = $(POLICY_CFLAGS)
libicd_policy_any_la_LDFLAGS = $(POLICY_LDFLAGS) -avoid-version
libicd_policy_any_la_LIBADD = $(ICD_LIBS) ../support/libicd_log.la
libicd_policy_any_la_SOURCES = policy_any.c

MAINTAINERCLEANFILES = Makefile.in
