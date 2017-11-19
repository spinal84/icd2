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
