#ifndef ICD_DBUS_H
#define ICD_DBUS_H

#include <glib.h>

#include <dbus/dbus.h>
/* while dbus is under construction, do this */
#include <dbus/dbus-glib-lowlevel.h>

struct icd_dbus_mcall_table {
  const gchar *name;
  const gchar *mcall_sig;
  const gchar *reply_sig;
  DBusObjectPathMessageFunction handler_fn;
};

struct icd_dbus_sig_table {
  const gchar *name;
  const gchar *mcall_sig;
};

struct icd_dbus_prop_table {
  const gchar *name;
};

gboolean icd_dbus_connect_system_path (const char *path,
                                       DBusObjectPathMessageFunction cb,
                                       void *user_data);
gboolean icd_dbus_disconnect_system_path (const char* path);

gboolean icd_dbus_connect_system_bcast_signal (const char *interface,
                                               DBusHandleMessageFunction cb,
                                               void *user_data,
                                               const char *extra_filters);

gboolean icd_dbus_disconnect_system_bcast_signal (const char *interface,
                                                  DBusHandleMessageFunction cb,
                                                  void *user_data,
                                                  const char *extra_filters);

gboolean icd_dbus_register_system_service (const char *path,
                                           const char *service,
                                           guint service_flags,
                                           DBusObjectPathMessageFunction cb,
                                           void *user_data);

void icd_dbus_unregister_system_service (const char *path,
                                         const char *service);

DBusPendingCall *icd_dbus_send_system_mcall (DBusMessage *message,
                                             gint timeout,
                                             DBusPendingCallNotifyFunction cb,
                                             void *user_data);

gboolean icd_dbus_send_system_msg (DBusMessage *message);


typedef void
(*icd_dbus_get_unique_name_cb_fn) (const gchar *name,
                                   const gchar *id,
                                   gpointer user_data);

void icd_dbus_cancel_unique_name (DBusPendingCall *pending);

gboolean icd_dbus_get_unique_name (const gchar *name,
                                   icd_dbus_get_unique_name_cb_fn cb,
                                   gpointer user_data);

void icd_dbus_close (void);

#endif
