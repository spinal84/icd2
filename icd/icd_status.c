#include <osso-ic-dbus.h>
#include "icd_iap.h"
#include "icd_dbus_api.h"
#include "icd_dbus.h"
#include "icd_log.h"

#define ICD_STATUS_DISCONNECTING "DISCONNECTING"

static void
icd_status_send_signal(const char *network_type, const char *id,
                       const char *state_name, const char *dbus_dest,
                       const char *uierr)
{
  DBusMessage *msg;

  if (!id || !network_type)
  {
    ILOG_CRIT("illegal value(s) for network_type '%s' or id '%s'",
              network_type, id);
  }
  else
  {
    msg = dbus_message_new_signal("/com/nokia/icd", "com.nokia.icd",
                                  ICD_STATUS_CHANGED_SIG);
    if (msg)
    {
      if (dbus_dest)
        dbus_message_set_destination(msg, dbus_dest);

      if (!uierr)
        uierr = "";

      if (dbus_message_append_args(msg,
                                   DBUS_TYPE_STRING, &id,
                                   DBUS_TYPE_STRING, &network_type,
                                   DBUS_TYPE_STRING, &state_name,
                                   DBUS_TYPE_STRING, &uierr,
                                   DBUS_TYPE_INVALID) &&
          icd_dbus_send_system_msg(msg))
      {
        ILOG_INFO("'%s' type '%s' " ICD_STATUS_CHANGED_SIG
                  "with status %s, '%s' sent to '%s'", id, network_type,
                  state_name, uierr, dbus_dest);
      }
      else
        ILOG_CRIT("could not send " ICD_STATUS_CHANGED_SIG);

      dbus_message_unref(msg);
    }
    else
      ILOG_CRIT("could not create "ICD_STATUS_CHANGED_SIG" message");
  }
}

void
icd_status_disconnect(struct icd_iap *iap, const gchar *dbus_destination,
                      const gchar *err_str)
{
  gchar *id = iap->id;
  gchar *network_type = iap->connection.network_type;

  if (!id || iap->id_is_local)
    id = iap->connection.network_id;

  icd_status_send_signal(network_type, id, ICD_STATUS_DISCONNECTING,
                         dbus_destination, err_str);
  icd_dbus_api_update_state(iap, dbus_destination, ICD_STATE_DISCONNECTING);
}

void
icd_status_limited_conn(struct icd_iap *iap, const gchar *dbus_destination,
                        const gchar *err_str)
{
  gchar *id = iap->id;
  const char *state_name;
  enum icd_connection_state state;

  if (!id || iap->id_is_local)
    id = iap->connection.network_id;

  state_name = "NETWORKUP";

  if (!iap->limited_conn)
    state_name = "NETWORKDOWN";

  icd_status_send_signal(iap->connection.network_type, id, state_name,
                         dbus_destination, err_str);

  if (iap->limited_conn)
    state = ICD_STATE_LIMITED_CONN_ENABLED;
  else
    state = ICD_STATE_LIMITED_CONN_DISABLED;

  icd_dbus_api_update_state(iap, dbus_destination, state);
}

void
icd_status_connect(struct icd_iap *iap, const gchar *dbus_destination,
                   const gchar *err_str)
{
  gchar *id;

  if (!iap->id || iap->id_is_local)
    id = iap->connection.network_id;
  else
    id = iap->id;

  icd_status_send_signal(iap->connection.network_type, id, "CONNECTING",
                         dbus_destination, err_str);
  icd_dbus_api_update_state(iap, dbus_destination, ICD_STATE_CONNECTING);
}

void
icd_status_connected(struct icd_iap *iap, const gchar *dbus_destination,
                     const gchar *err_str)
{
  gchar *id;

  if (!iap->id || iap->id_is_local)
    id = iap->connection.network_id;
  else
    id = iap->id;

  icd_status_send_signal(iap->connection.network_type, id, "CONNECTED",
                         dbus_destination, err_str);
  icd_dbus_api_update_state(iap, dbus_destination, ICD_STATE_CONNECTED);
}

void
icd_status_disconnected(struct icd_iap *iap, const gchar *dbus_destination,
                        const gchar *err_str)
{
  gchar *id;

  if (!iap->id || iap->id_is_local)
    id = iap->connection.network_id;
  else
    id = iap->id;

  icd_status_send_signal(iap->connection.network_type, id, "IDLE",
                         dbus_destination, err_str);
  icd_dbus_api_update_state(iap, dbus_destination, ICD_STATE_DISCONNECTED);
}
