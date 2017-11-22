#include <string.h>
#include <dbus/dbus.h>
#include <osso-ic.h>
#include "icd_dbus_api.h"
#include "icd_dbus.h"
#include "icd_log.h"
#include "icd_scan.h"
#include "icd_network_api.h"
#include "icd_context.h"
#include "icd_request.h"
#include "icd_name_owner.h"
#include "icd_gconf.h"

/** ICd2 D-Bus API data structure */
struct icd_dbus_api_listeners {
  /** dbus apps receiving scan results */
  GSList *scan_listeners;
};

/** Helper structure for starting a scan */
struct icd_dbus_api_scan_helper {
  /**  The reply message iterator */
  DBusMessageIter *reply_str_iter;

  /** scan listener */
  gchar *dbus_dest;

  /** passive/active scan type */
  guint scan_type;
};

struct icd_dbus_api_foreach_data;
/**
 * @brief Template for the D-Bus data sending function
 *
 * @param iap the IAP
 * @param foreach_data foreach data structure
 *
 * @return TRUE on success, FALSE on error
 *
*/
typedef gboolean(* icd_dbus_api_foreach_send_fn)(struct icd_iap *iap, struct icd_dbus_api_foreach_data *foreach_data);

/** data structure to keep track of the number of connections and the sender */
struct icd_dbus_api_foreach_data {
  /** number of connections */
  guint connections;

  /** the D-Bus sender or NULL */
  const gchar *sender;

  /** unction that sends data to D-Bus applications */
  icd_dbus_api_foreach_send_fn send_fn;
};


static DBusHandlerResult icd_dbus_api_scan_cancel(DBusConnection *conn,
                                                  DBusMessage *msg,
                                                  void *user_data);

/** method calls provided */
static const struct icd_dbus_mcall_table icd_dbus_api_mcalls[] = {
 /*{ICD_DBUS_API_SCAN_REQ, "u", "as", icd_dbus_api_scan_req},
 {ICD_DBUS_API_SCAN_REQ, "uas", "as", icd_dbus_api_scan_req},*/
 {ICD_DBUS_API_SCAN_CANCEL, "", "", icd_dbus_api_scan_cancel},
 /*{ICD_DBUS_API_CONNECT_REQ, "u", "", icd_dbus_api_connect_req},
 {ICD_DBUS_API_CONNECT_REQ, "ua(sussuay)", "", icd_dbus_api_connect_req},
 {ICD_DBUS_API_SELECT_REQ, "u", "", icd_dbus_api_select_req},
 {ICD_DBUS_API_DISCONNECT_REQ, "usussuay", "", icd_dbus_api_disconnect_req},
 {ICD_DBUS_API_DISCONNECT_REQ, "u", "", icd_dbus_api_disconnect_req},
 {ICD_DBUS_API_STATE_REQ, "sussuay", "u", icd_dbus_api_state_req},
 {ICD_DBUS_API_STATE_REQ, "", "u", icd_dbus_api_state_req},
 {ICD_DBUS_API_STATISTICS_REQ, "sussuay", "u", icd_dbus_api_statistics_req},
 {ICD_DBUS_API_STATISTICS_REQ, "", "u", icd_dbus_api_statistics_req},
 {ICD_DBUS_API_ADDRINFO_REQ, "sussuay", "u", icd_dbus_api_addrinfo_req},
 {ICD_DBUS_API_ADDRINFO_REQ, "", "u", icd_dbus_api_addrinfo_req},*/
 {NULL}
};

/**
 * @brief Get the dbus api data structure
 *
 * @return the dbus api data structure
 *
 */
static struct icd_dbus_api_listeners **
icd_dbus_api_listeners_get(void)
{
  static struct icd_dbus_api_listeners *listeners = NULL;

  if (!listeners)
     listeners = g_new0(struct icd_dbus_api_listeners, 1);

   return &listeners;
}

/**
 * @brief Receive scan results and send them via D-Bus
 *
 * @param status status of this network
 * @param srv_provider service provider entry; guaranteed to exist only for the
 * lifetime of this callback function
 * @param cache_entry scan results; guaranteed to exist only for the lifetime of
 * this callback function
 * @param user_data D-Bus app that requested the scan
 *
 */
static void
icd_dbus_api_scan_result(enum icd_scan_status status,
                         const struct icd_scan_srv_provider *srv_provider,
                         const struct icd_scan_cache *cache_entry,
                         gpointer user_data)
{
  DBusMessage *message;
  const gchar **service_id;
  const gchar *network_id;
  const gchar *const *service_type;
  const gchar **service_name;
  const gchar **network_type;
  const gchar **network_name;
  const gchar **station_id;
  const dbus_uint32_t *service_attrs;
  const dbus_int32_t *service_priority;
  dbus_uint32_t uzero = 0;
  dbus_int32_t izero = 0;
  const gchar *empty = "";

  message = dbus_message_new_signal("/com/nokia/icd2", "com.nokia.icd2", "scan_result_sig");

  if (!message)
  {
    ILOG_CRIT("dbus api out of memory when creating scan signal");
    return;
  }

  if (!dbus_message_set_destination(message, (const char *)user_data))
  {
    ILOG_CRIT("dbus api out of memory when setting destination");
    goto out;
  }

  network_id = cache_entry->network_id ? cache_entry->network_id : empty;

  if (srv_provider)
  {
    service_type = srv_provider->service_type ?
          (const gchar**)&srv_provider->service_type : &empty;
    service_name = srv_provider->service_name ?
          (const gchar**)&srv_provider->service_name : &empty;
    service_id = srv_provider->service_id ?
          (const gchar**)&srv_provider->service_id : &empty;
    service_priority = &srv_provider->service_priority;
    service_attrs = &srv_provider->service_attrs;
  }
  else
  {
    service_name = &empty;
    service_priority = &izero;
    service_attrs = &uzero;
    service_type = &empty;
    service_id = &empty;
  }

  network_type = cache_entry->network_type ?
        (const gchar**)&cache_entry->network_type : &empty;
  network_name = cache_entry->network_name ?
        (const gchar**)&cache_entry->network_name : &empty;
  station_id = cache_entry->station_id ?
        (const gchar**)&cache_entry->station_id : &empty;

  if (dbus_message_append_args(message,
                               DBUS_TYPE_UINT32,  &status,
                               DBUS_TYPE_UINT32, cache_entry,
                               DBUS_TYPE_STRING, service_type,
                               DBUS_TYPE_STRING, service_name,
                               DBUS_TYPE_UINT32, service_attrs,
                               DBUS_TYPE_STRING, service_id,
                               DBUS_TYPE_INT32, service_priority,
                               DBUS_TYPE_STRING, network_type,
                               DBUS_TYPE_STRING, network_name,
                               DBUS_TYPE_UINT32, &cache_entry->network_attrs,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                               &network_id, strlen(network_id) + 1,
                               DBUS_TYPE_INT32, &cache_entry->network_priority,
                               DBUS_TYPE_INT32, &cache_entry->signal,
                               DBUS_TYPE_STRING, station_id,
                               DBUS_TYPE_INT32, &cache_entry->dB,
                               DBUS_TYPE_INVALID))
  {
    icd_dbus_send_system_msg(message);
  }
  else
    ILOG_CRIT("dbus api out of memory when appending scan signal args");

out:
  dbus_message_unref(message);
}

/**
 * @brief Notify ICd2 D-Bus API when an app goes away
 *
 * @param dbus_dest D-Bus sender id
 *
 * @return if D-Bus sender was removed, FALSE otherwise
 *
 */
gboolean
icd_dbus_api_app_exit(const gchar *dbus_dest)
{
  gboolean rv = FALSE;
  struct icd_dbus_api_listeners **listeners = icd_dbus_api_listeners_get();
  GSList *l = (*listeners)->scan_listeners;

  while (l)
  {
    gchar *listener = (gchar *)l->data;
    GSList *next = l->next;

    if (listener)
    {
      if (!strcmp(listener, dbus_dest))
      {
        ILOG_INFO("dbus api removed scanning for app '%s'", dbus_dest);

        (*listeners)->scan_listeners =
            g_slist_delete_link((*listeners)->scan_listeners, l);
        icd_scan_results_unregister(icd_dbus_api_scan_result, listener);
        icd_name_owner_remove_filter(dbus_dest);
        g_free(listener);
        rv = TRUE;
      }
    }

    l = next;
  }

  return rv;
}

/**
 * @brief Append a the network type of the successfully started network scan to
 * the iterator position
 *
 * @param network_type network type to start scan for
 * @param scan_start scan helper structure
 *
 * @return TRUE on success, FALSE if the scan was not started
 *
 * @todo UI designer does not want to have the "scanning" icon blinking in this
 * case
 *
 */
static gboolean
icd_dbus_api_scan_append(gchar *network_type,
                         struct icd_dbus_api_scan_helper *scan_start)
{
  gboolean
      rv = icd_scan_results_request(network_type, scan_start->scan_type == 1,
                                    icd_dbus_api_scan_result,
                                    scan_start->dbus_dest);
  if (rv)
  {
    ILOG_INFO("dbus api successfully started '%s' scan for '%s'", network_type,
              scan_start->dbus_dest);

    dbus_message_iter_append_basic(scan_start->reply_str_iter,
                                   DBUS_TYPE_STRING, &network_type);
  }

  return rv;
}

void
icd_dbus_api_deinit(void)
{
  icd_dbus_unregister_system_service(ICD_DBUS_API_PATH, ICD_DBUS_API_INTERFACE);
}

static DBusHandlerResult
icd_dbus_api_request(DBusConnection *connection, DBusMessage *message,
                     void *user_data)
{
  DBusMessage *err_msg;
  int i = 0;
  const char *iface = dbus_message_get_interface(message);

  if (iface && !strcmp(iface, ICD_DBUS_API_INTERFACE))
  {
    while (icd_dbus_api_mcalls[i].name)
    {
      if (!strcmp(dbus_message_get_member(message),
                  icd_dbus_api_mcalls[i].name))
      {
        if (icd_dbus_api_mcalls[i].mcall_sig &&
            dbus_message_has_signature(message,
                                       icd_dbus_api_mcalls[i].mcall_sig))
        {
          if (icd_dbus_api_mcalls[i].handler_fn)
          {
            ILOG_INFO("Received %s.%s (%s) request",
                      dbus_message_get_interface(message),
                      dbus_message_get_member(message),
                      dbus_message_get_signature(message));

            return icd_dbus_api_mcalls[i].handler_fn(connection, message,
                                                     user_data);
          }
        }
      }

      i++;
    }
  }

  ILOG_INFO("received '%s.%s' request has no handler implemented",
            dbus_message_get_interface(message),
            dbus_message_get_member(message));

  err_msg = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED,
                                   "Unsupported interface or method");
  icd_dbus_send_system_msg(err_msg);
  dbus_message_unref(err_msg);

  return DBUS_HANDLER_RESULT_HANDLED;
}

gboolean
icd_dbus_api_init(void)
{
  icd_dbus_api_update_state(NULL, NULL, ICD_STATE_DISCONNECTED);

  return icd_dbus_register_system_service(ICD_DBUS_API_PATH,
                                          ICD_DBUS_API_INTERFACE,
                                          DBUS_NAME_FLAG_REPLACE_EXISTING |
                                          DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                          icd_dbus_api_request,
                                          NULL);
}

static DBusHandlerResult
icd_dbus_api_scan_cancel(DBusConnection *conn, DBusMessage *msg,
                         void *user_data)
{
  DBusMessage *reply;

  if (icd_dbus_api_app_exit(dbus_message_get_sender(msg)))
    reply = dbus_message_new_method_return(msg);

  else
  {
    reply = dbus_message_new_error(msg, DBUS_ERROR_FAILED,
                                   "Scan results have not been requested");
  }

  if (!reply)
  {
    reply = dbus_message_new_error(msg, DBUS_ERROR_NO_MEMORY,
                                   "Out of memory when creating reply");

    if (!reply)
      return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  icd_dbus_send_system_msg(reply);
  dbus_message_unref(reply);

  return DBUS_HANDLER_RESULT_HANDLED;
}

gboolean
icd_dbus_api_update_state(struct icd_iap *iap, const gchar *destination,
                          const enum icd_connection_state state)
{
  DBusMessage *msg;
  const gchar *network_id;
  const gchar **service_type;
  const gchar *network_type;
  const gchar **service_id;
  const gchar **err_str;
  const gchar *empty = "";

  msg = dbus_message_new_signal(ICD_DBUS_API_PATH,
                                ICD_DBUS_API_INTERFACE,
                                ICD_DBUS_API_STATE_SIG);

  if (!msg || !dbus_message_set_destination(msg, destination))
  {
      ILOG_ERR("dbus api could not create state signal");

      if (msg)
        dbus_message_unref(msg);

      return FALSE;
  }

  if (iap)
  {
    network_id = iap->connection.network_id ?
          (const gchar *)iap->connection.network_id : empty;
    service_type = iap->connection.service_type ?
          (const gchar **)&iap->connection.service_type : &empty;
    service_id = iap->connection.service_id ?
          (const gchar **)&iap->connection.service_id : &empty;
    network_type = iap->connection.network_type ?
          (const gchar *)&iap->connection.network_type : empty;
    err_str = iap->err_str ? (const gchar **)&iap->err_str : &empty;

    if (!dbus_message_append_args(
          msg,
          DBUS_TYPE_STRING, service_type,
          DBUS_TYPE_UINT32,&iap->connection.service_attrs,
          DBUS_TYPE_STRING, service_id,
          DBUS_TYPE_STRING, network_type,
          DBUS_TYPE_UINT32, &iap->connection.network_attrs,
          DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
          &network_id, strlen(network_id) + 1,
          DBUS_TYPE_STRING, err_str,
          DBUS_TYPE_INVALID))
    {
      ILOG_ERR("dbus api could not add attributes to state signal");
      dbus_message_unref(msg);
      return FALSE;
    }
  }

  if (!dbus_message_append_args(msg,
                                DBUS_TYPE_UINT32, &state,
                                DBUS_TYPE_INVALID))
  {
    ILOG_ERR("dbus api could not add state to empty state signal");
    dbus_message_unref(msg);
    return FALSE;
  }

  icd_dbus_send_system_msg(msg);
  dbus_message_unref(msg);

  return TRUE;
}

static gboolean
icd_dbus_api_state_send(struct icd_iap *iap,
                        struct icd_dbus_api_foreach_data *foreach_data)
{
  const gchar *dest = foreach_data->sender;
  gboolean rv;

  switch (iap->state)
  {
    case ICD_IAP_STATE_SCRIPT_PRE_UP:
    case ICD_IAP_STATE_LINK_UP:
    case ICD_IAP_STATE_LINK_POST_UP:
    case ICD_IAP_STATE_IP_UP:
    case ICD_IAP_STATE_SCRIPT_POST_UP:
    case ICD_IAP_STATE_SAVING:
      rv = icd_dbus_api_update_state(iap, dest, ICD_STATE_CONNECTING);
      break;
    case ICD_IAP_STATE_SRV_UP:
    {
      enum icd_connection_state conn_state;

      if (iap->limited_conn)
        conn_state = ICD_STATE_LIMITED_CONN_ENABLED;
      else
        conn_state = ICD_STATE_CONNECTING;

      rv = icd_dbus_api_update_state(iap, dest, conn_state);
      break;
    }
    case ICD_IAP_STATE_CONNECTED:
      rv = icd_dbus_api_update_state(iap, dest, ICD_STATE_CONNECTED);
      break;
    case ICD_IAP_STATE_CONNECTED_DOWN:
    case ICD_IAP_STATE_SRV_DOWN:
    case ICD_IAP_STATE_IP_DOWN:
    case ICD_IAP_STATE_LINK_PRE_DOWN:
    case ICD_IAP_STATE_LINK_DOWN:
    case ICD_IAP_STATE_SCRIPT_POST_DOWN:
      rv = icd_dbus_api_update_state(iap, dest, ICD_STATE_DISCONNECTING);
      break;
    default:
      rv = icd_dbus_api_update_state(iap, dest, ICD_STATE_DISCONNECTED);
      break;
  }

  return rv;
}

static gboolean
icd_dbus_api_state_scanning(struct icd_network_module *module,
                            gpointer user_data)
{
  struct icd_dbus_api_foreach_data *data =
      (struct icd_dbus_api_foreach_data *)user_data;
  GSList *l;
  const enum icd_connection_state state = ICD_STATE_SEARCH_START;

  if (!module->scan_progress)
    return TRUE;

  for ( l = module->network_types; l; l = l->next )
  {
    const gchar *network_type = (const gchar *)l->data;

    if (network_type)
    {
        gboolean sent;
        DBusMessage *msg = dbus_message_new_signal(ICD_DBUS_API_PATH,
                                                   ICD_DBUS_API_INTERFACE,
                                                   ICD_DBUS_API_STATE_SIG);

      if (msg && dbus_message_set_destination(msg, data->sender))
      {
        if (dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &network_type,
                                     DBUS_TYPE_UINT32, &state,
                                     DBUS_TYPE_INVALID))
        {
          sent = icd_dbus_send_system_msg(msg);

          if (sent)
            data->connections++;
        }
        else
          ILOG_ERR("dbus api could not add attributes to scsn state signal");
      }
      else
      {
        ILOG_ERR("dbus api could not create scan state signal");

        if (!msg)
          continue;
      }

      dbus_message_unref(msg);
    }
  }

  return TRUE;
}

static DBusHandlerResult
icd_dbus_api_state_req(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
  DBusMessage *reply;
  struct icd_context *icd_ctx;
  struct icd_dbus_api_foreach_data data;

  reply = dbus_message_new_method_return(msg);

  if (!reply)
  {
    ILOG_ERR("dbus api cannot create state req mcall return");
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  data.connections = 0;
  data.send_fn = icd_dbus_api_state_send;
  data.sender = dbus_message_get_sender(msg);

  icd_dbus_api_foreach_iap_req(msg, &data);
  icd_ctx = icd_context_get();
  icd_network_api_foreach_module(icd_ctx, icd_dbus_api_state_scanning, &data);

  if (dbus_message_append_args(reply,
                               DBUS_TYPE_UINT32, &data.connections,
                               DBUS_TYPE_INVALID))
  {
    icd_dbus_send_system_msg(reply);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  dbus_message_unref(reply);

  ILOG_ERR("dbus_api could not add args to mcall return");

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
