#include "icd_iap.h"
#include "icd_dbus_api.h"

#define ICD_STATUS_DISCONNECTING "DISCONNECTING"

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
