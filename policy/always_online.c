#include <gconf/gconf-client.h>
#include <osso-ic-gconf.h>
#include <osso-ic.h>
#include <mce/dbus-names.h>
#include <mce/mode-names.h>

#include <string.h>

#include "policy_api.h"
#include "icd_dbus.h"
#include "icd_log.h"

#define CHANGE_WHILE_CONNECTED_KEY ICD_GCONF_NETWORK_MAPPING "/change_while_connected"
#define AUTO_CONNECT_KEY ICD_GCONF_NETWORK_MAPPING "/auto_connect"
#define SEARCH_INTERVAL_KEY ICD_GCONF_NETWORK_MAPPING "/search_interval"

struct policy_always_online_data {
  gint number_of_connections;
  guint check_connections_timeout_id;
  gint iap_count;
  gint search_interval;
  guint always_online_timer_id;
  gboolean auto_connect;
  gboolean always_change;
  gboolean gconf_value_changed;
  guint network_type_notify;
  guint iap_notify;
  gboolean offline_mode;
  DBusPendingCall *get_device_mode_pending;
  gboolean devmode_filter_set;
  icd_policy_request_make_new_fn make_request;
  icd_policy_network_priority_fn priority_fn;
  icd_policy_service_module_check_fn srv_check_fn;
  gint network_priority;
};

static void always_online_run(struct policy_always_online_data *data,
                              gboolean make_new_request);

static int
get_iap_count()
{
  GConfClient *gconf = gconf_client_get_default();
  GSList *l;
  int count = 0;

  l = gconf_client_all_dirs(gconf, ICD_GCONF_PATH, NULL);

  while (l)
  {
    GSList *next;

    g_free(l->data);
    count++;
    next = g_slist_remove_link(l, l);
    g_slist_free_1(l);
    l = next;
  }

  g_object_unref(gconf);

  return count;
}

static void
cancel_always_online_timer(gpointer user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;

  if (data->always_online_timer_id )
  {
    ILOG_INFO("always online timeout id %d cancelled",
              data->always_online_timer_id);
    g_source_remove(data->always_online_timer_id);
    data->always_online_timer_id = 0;
  }
}

static gboolean
always_online_timer_cb(gpointer user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;

  ILOG_DEBUG("always online timer %d triggered", data->always_online_timer_id);
  always_online_run(data, TRUE);

  return TRUE;
}

static void
parse_device_mode_ind(DBusMessage *message,
                      struct policy_always_online_data *data)
{
  gboolean offline_mode;
  gchar *mode;

  if (dbus_message_get_args(message, NULL,
                            DBUS_TYPE_STRING, &mode,
                            DBUS_TYPE_INVALID))
  {
    if (!strcmp(mode, MCE_FLIGHT_MODE) || !strcmp(mode, MCE_OFFLINE_MODE))
    {
      offline_mode = TRUE;

      if (!data->offline_mode)
      {
        ILOG_INFO("always online: offline mode");
        cancel_always_online_timer(data);
      }
    }
    else
    {
      offline_mode = FALSE;

      if (data->offline_mode)
      {
        ILOG_INFO("always online: normal mode");
        cancel_always_online_timer(data);
        data->always_online_timer_id =
            g_timeout_add(2000, always_online_timer_cb, data);

        ILOG_INFO("always online waiting 2s for the normal mode to propagate through the rest of the system, timer id is %d",
                  data->always_online_timer_id);
      }
    }

    if (offline_mode == data->offline_mode)
    {
      ILOG_DEBUG("always online received same state, %s",
                 offline_mode ? "offline mode" : "normal mode");
    }
    else
      data->offline_mode = offline_mode;
  }
  else
    ILOG_ERR("always online could not parse flight mode message");
}

static DBusHandlerResult
device_mode_ind_filter(DBusConnection *connection, DBusMessage *message,
                       void *user_data)
{
  if (dbus_message_is_signal(message, MCE_SIGNAL_IF, MCE_DEVICE_MODE_SIG))
  {
    parse_device_mode_ind(message,
                          (struct policy_always_online_data *)user_data);
  }

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
get_device_mode_cb(DBusPendingCall *pending, void *user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;
  DBusMessage *message = dbus_pending_call_steal_reply(pending);

  dbus_pending_call_unref(data->get_device_mode_pending);
  data->get_device_mode_pending = NULL;
  parse_device_mode_ind(message, data);
  dbus_message_unref(message);
}

static void
always_online_run(struct policy_always_online_data *data,
                  gboolean make_new_request)
{
  gboolean module_loaded;

  data->gconf_value_changed = FALSE;

  if (data->always_online_timer_id)
    cancel_always_online_timer(data);

  module_loaded = data->srv_check_fn(NULL);

  if ((!data->iap_count && !module_loaded) ||
      !data->auto_connect || data->search_interval <= 0 ||
      (data->number_of_connections && !data->always_change) ||
      data->network_priority )
  {
    ILOG_DEBUG("always online not run because iap count %d <= 0; "
               "srv_provider %s; auto_conn is '%s'; timeout %d <= 0; number of "
               "connections %d > 0 and always change %s; priority %d",
               data->iap_count, module_loaded ? "TRUE" : "FALSE",
               data->auto_connect? "TRUE" : "FALSE", data->search_interval,
               data->number_of_connections,
               data->always_change ? "TRUE" : "FALSE", data->network_priority);

    return;
  }

  ILOG_DEBUG("always online run because iap count %d; srv_provider %s; "
             "auto_conn is '%s'; timeout %d; number of connections %d and "
             "always change %s; priority %d", data->iap_count,
             module_loaded ? "TRUE" : "FALSE",
             data->auto_connect? "TRUE" : "FALSE", data->search_interval,
             data->number_of_connections,
             data->always_change ? "TRUE" : "FALSE", data->network_priority);

  if (make_new_request)
  {
    guint policy_attrs = ICD_POLICY_ATTRIBUTE_NO_INTERACTION |
                         ICD_POLICY_ATTRIBUTE_ALWAYS_ONLINE;

    ILOG_INFO("always online making new request");

    if (data->always_change)
      policy_attrs |= ICD_POLICY_ATTRIBUTE_ALWAYS_ONLINE_CHANGE;

    data->make_request(policy_attrs, NULL, 0, NULL, NULL, 0, OSSO_IAP_ANY);
  }

  data->always_online_timer_id =
      g_timeout_add(1000 * data->search_interval, always_online_timer_cb, data);

  ILOG_INFO("always online timer id %d added", data->always_online_timer_id);
}

static gboolean
check_connections_cb(gpointer user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;
  int iap_count = get_iap_count();

  ILOG_DEBUG("always online found %d IAPs in gconf", iap_count);

  data->check_connections_timeout_id = 0;

  if (!data->iap_count && iap_count)
  {
    data->iap_count = iap_count;
    ILOG_INFO("always online found one newly created IAP in gconf, trying to activate");
  }
  else
  {
    data->iap_count = iap_count;

    if (!data->gconf_value_changed)
      return FALSE;

    ILOG_INFO("always online values changed, trying to activate");
  }

  always_online_run(data, TRUE);

  return FALSE;
}

static void
network_type_notify_cb(GConfClient *client, guint cnxn_id, GConfEntry *entry,
                       gpointer user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;
  const char *key = gconf_entry_get_key(entry);

  if (key)
  {
    GConfValue *val = gconf_entry_get_value(entry);

    if (!strcmp(key, AUTO_CONNECT_KEY))
    {
      if (G_VALUE_HOLDS(val, GCONF_VALUE_LIST))
        data->auto_connect = !!gconf_value_get_list(val);
      else
        data->auto_connect = FALSE;

      ILOG_INFO("always online connect automatically: %s",
                data->auto_connect ? "yes" : "no");

      data->gconf_value_changed = TRUE;
    }
    else if (!strcmp(key, SEARCH_INTERVAL_KEY))
    {
      if (G_VALUE_HOLDS(val, GCONF_VALUE_INT))
        data->search_interval = gconf_value_get_int(val);
      else
        data->search_interval = 0;

      ILOG_INFO("always online timer set to %d seconds(s)",
                data->search_interval);
      data->gconf_value_changed = TRUE;
    }
    else if (!strcmp(key, CHANGE_WHILE_CONNECTED_KEY))
    {
      if (G_VALUE_HOLDS(val, GCONF_VALUE_BOOL))
        data->always_change = gconf_value_get_bool(val);
      else
        data->always_change = FALSE;

      ILOG_DEBUG("always online run while connected: %s",
                 data->always_change ? "yes" : "no");

      data->gconf_value_changed = TRUE;
    }
  }

  if (!data->check_connections_timeout_id)
  {
    data->check_connections_timeout_id =
        g_timeout_add(500, check_connections_cb, data);
  }
}

static void
iap_notify_cb(GConfClient *client, guint cnxn_id, GConfEntry *entry,
              gpointer user_data)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)user_data;

  if (gconf_entry_get_value(entry) && !data->check_connections_timeout_id)
  {
    ILOG_DEBUG("always online will soon check whether connections were added");

    data->check_connections_timeout_id =
        g_timeout_add(500, check_connections_cb, data);
  }
}

static void
icd_policy_always_online_destruct(gpointer *private)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)*private;
  GConfClient *gconf = gconf_client_get_default();

  if (data->get_device_mode_pending)
  {
    ILOG_INFO("always online cancelling pending call");
    dbus_pending_call_cancel(data->get_device_mode_pending);
    data->get_device_mode_pending = 0;
  }

  if (data->devmode_filter_set)
    icd_dbus_disconnect_system_bcast_signal(MCE_SIGNAL_IF,
                                            device_mode_ind_filter, data,
                                            "member='" MCE_DEVICE_MODE_SIG "'");

  if (data->network_type_notify)
  {
    gconf_client_remove_dir(gconf, ICD_GCONF_NETWORK_MAPPING, NULL);
    gconf_client_notify_remove(gconf, data->network_type_notify);
  }

  if (data->iap_notify)
  {
    gconf_client_remove_dir(gconf, ICD_GCONF_PATH, NULL);
    gconf_client_notify_remove(gconf, data->iap_notify);
  }

  g_object_unref(gconf);
  cancel_always_online_timer(data);

  if (data->check_connections_timeout_id)
  {
    ILOG_INFO("always online iap count id %d cancelled",
              data->check_connections_timeout_id);
    g_source_remove(data->check_connections_timeout_id);
    data->check_connections_timeout_id = 0;
  }

  g_free(data);
  *private = NULL;
}

static void
icd_policy_always_online_disconnected(struct icd_policy_request *network,
                                      const gchar *err_str,
                                      GSList *existing_connections,
                                      gpointer *private)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)*private;

  if (data->number_of_connections)
  {
    data->number_of_connections--;

    ILOG_DEBUG("always online connection count %d",
               data->number_of_connections);

    if (!data->number_of_connections)
      data->network_priority = 0;

    always_online_run(data, err_str ? TRUE : FALSE);
  }
  else
    ILOG_DEBUG("always online sees network disconnected, but none connected");
}

static void
icd_policy_always_online_connected(struct icd_policy_request *network,
                                   GSList *existing_connections,
                                   gpointer *privat)
{
  struct policy_always_online_data *data =
      (struct policy_always_online_data *)*privat;
  gint network_priority;

  data->number_of_connections = g_slist_length(existing_connections);

  ILOG_DEBUG("always online connection count %d", data->number_of_connections);

  if (data->always_change && data->priority_fn)
  {
    if (data->priority_fn(network->service_type, network->service_id,
                          network->network_type, network->network_attrs,
                          &network_priority))
    {
      ILOG_DEBUG("always online timer not cancelled because higher priority network exists and always_change is set (%s/0x%04x/%s/%d)",
                 network->network_type, network->network_attrs,
                 network->network_id, network_priority);
      data->network_priority = 0;
    }
    else
    {
      cancel_always_online_timer(data);
      data->network_priority = network_priority;
    }
  }
  else
    cancel_always_online_timer(data);
}

void
icd_policy_init(struct icd_policy_api *policy_api,
                icd_policy_nw_add_fn add_network,
                icd_policy_request_merge_fn merge_requests,
                icd_policy_request_make_new_fn make_request,
                icd_policy_scan_start_fn scan_start,
                icd_policy_scan_stop_fn scan_stop,
                icd_policy_nw_close_fn nw_close,
                icd_policy_network_priority_fn priority,
                icd_policy_service_module_check_fn srv_check)
{
  GConfClient *gconf = gconf_client_get_default();
  struct policy_always_online_data *data =
      g_new0(struct policy_always_online_data, 1);
  GError *error = NULL;
  GConfValue *val;
  DBusMessage *message;

  policy_api->private = data;

  data->make_request = make_request;
  data->offline_mode = TRUE;

  val = gconf_client_get(gconf, AUTO_CONNECT_KEY, NULL);
  data->auto_connect = G_VALUE_HOLDS(val, GCONF_VALUE_LIST) &&
      gconf_value_get_list(val);

  ILOG_INFO("always online connect automatically: %s",
            data->auto_connect ? "Yes" : "No");

  data->always_change = gconf_client_get_bool(gconf,
                                              CHANGE_WHILE_CONNECTED_KEY, NULL);

  ILOG_INFO("always online connection change: %s",
            data->always_change ? "Yes" : "No");

  data->search_interval = gconf_client_get_int(gconf, SEARCH_INTERVAL_KEY,
                                               NULL);

  ILOG_INFO("always online timeout defaults to %d minute(s)",
            data->search_interval);

  data->iap_count = get_iap_count();

  ILOG_INFO("always online defaults to %d IAPs in gconf", data->iap_count);

  g_object_unref(gconf);

  data->devmode_filter_set = icd_dbus_connect_system_bcast_signal(
        MCE_SIGNAL_IF, device_mode_ind_filter, data,
        "member='" MCE_DEVICE_MODE_SIG "'");

  if (!data->devmode_filter_set)
    goto failed;

  message = dbus_message_new_method_call(MCE_SERVICE,
                                         MCE_REQUEST_PATH,
                                         MCE_REQUEST_IF,
                                         MCE_DEVICE_MODE_GET);
  if (!message)
  {
    ILOG_CRIT("always online could not create flightmode request message");
    goto failed;
  }

  data->get_device_mode_pending =
      icd_dbus_send_system_mcall(message, 5000, get_device_mode_cb, data);

  if (!data->get_device_mode_pending)
  {
    ILOG_CRIT("always online could not send flightmode request");
    dbus_message_unref(message);
    goto failed;
  }

  gconf = gconf_client_get_default();
  data->network_type_notify = gconf_client_notify_add(
        gconf, ICD_GCONF_NETWORK_MAPPING, network_type_notify_cb, data, NULL,
        &error);

  if (!error)
  {
    gconf_client_add_dir(gconf, ICD_GCONF_NETWORK_MAPPING,
                         GCONF_CLIENT_PRELOAD_ONELEVEL, &error);

    if (!error)
    {
      data->iap_notify = gconf_client_notify_add(gconf, ICD_GCONF_PATH,
                                                 iap_notify_cb, data, NULL,
                                                 &error);

      if (!error)
      {
        gconf_client_add_dir(gconf, ICD_GCONF_PATH,
                             GCONF_CLIENT_PRELOAD_ONELEVEL, &error);

        if (!error)
        {
          g_object_unref(gconf);
          data->priority_fn = priority;
          data->srv_check_fn = srv_check;
          policy_api->connected = icd_policy_always_online_connected;
          policy_api->disconnected = icd_policy_always_online_disconnected;
          policy_api->destruct = icd_policy_always_online_destruct;
          policy_api->priority = priority;
          return;
        }
        else
          ILOG_ERR("always online gconf add dir error: %s", error->message);
      }
      else
        ILOG_ERR("always online gconf notification error: %s", error->message);
    }
    else
      ILOG_ERR("always online gconf add dir error: %s", error->message);
  }

  g_clear_error(&error);
  g_object_unref(gconf);

failed:
  ILOG_CRIT("always online failed to connect, always online disabled");
  icd_policy_always_online_destruct((gpointer *)&data);
}
