#include "icd_network_api.h"
#include "icd_scan.h"
#include "icd_log.h"

#include <string.h>

/** scan listener list data */
struct icd_scan_listener {
  /** network type */
  gchar *type;
  /** callback */
  icd_scan_cb_fn cb;
  /** callback data */
  gpointer user_data;
};

/**
 * helper structure for communicating module and expiration to hash table
 * remove callback
 */
struct icd_scan_expire_network_data {
  /** module */
  struct icd_network_module *module;
  /** expiration time */
  guint expire;
};

/** scan status name strings */
static const gchar const *icd_scan_status_names[] =
{
  "ICD_SCAN_NEW",
  "ICD_SCAN_UPDATE",
  "ICD_SCAN_NOTIFY",
  "ICD_SCAN_EXPIRE",
  "ICD_SCAN_COMPLETE"
};

/**
 * @brief Remove all matching listener callback - user data tuples from a module
 *
 * @param module the network module
 * @param cb the callback to remove or NULL to remove all callbacks
 * @param user_data user data to remove
 *
 */
void
icd_scan_listener_remove(struct icd_network_module *module, icd_scan_cb_fn cb,
                         gpointer user_data)
{
  GSList *l = module->scan_listener_list;

  while (l)
  {
    GSList *next = l->next;
    struct icd_scan_listener *scan_listener =
        (struct icd_scan_listener *)l->data;

    if (!cb ||
        (scan_listener && scan_listener->cb == cb &&
         scan_listener->user_data == user_data))
    {
      g_free(scan_listener->type);
      g_free(scan_listener);
      module->scan_listener_list =
          g_slist_delete_link(module->scan_listener_list, l);
    }

    l = next;
  }
}

/**
 * @brief Unregister all matching callback - user data tuples from receiving
 * scan results
 *
 * @param cb the same callback as given in icd_scan_results_request
 * @param user_data the same user_data as given in #icd_scan_results_request
 *
 * @return TRUE if the callback - user_data tuple existed and was removed;
 * FALSE otherwise
 *
 */
gboolean
icd_scan_results_unregister(icd_scan_cb_fn cb, gpointer user_data)
{
  GSList *l;
  gboolean rv = FALSE;

  if (!cb)
  {
    ILOG_ERR("cannot remove listener callback that is NULL");
    return rv;
  }

  for (l = icd_context_get()->nw_module_list; l; l = l->next)
  {
    struct icd_network_module *module = (struct icd_network_module *)l->data;

    if (!module)
      ILOG_ERR("network module in list is NULL");
    else
    {
      rv = TRUE;
      icd_scan_listener_remove(module, cb, user_data);
    }
  }

  return rv;
}

/**
 * @brief Set up the scan cache for a network module
 *
 * @param module network module
 *
 * @return TRUE on success, FALSE if scan cache already exists
 *
 */
gboolean
icd_scan_cache_init(struct icd_network_module *module)
{
  if (module->scan_cache_table)
  {
    ILOG_ERR("scan cache already exists");
    return FALSE;
  }

  module->scan_cache_table =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  return TRUE;
}

/**
 * @brief  Free an #icd_scan_cache structure
 *
 * @param cache_entry cache entry to free
 *
 */
void
icd_scan_cache_entry_free(struct icd_scan_cache *cache_entry)
{
  GSList *l;

  for (l = cache_entry->srv_provider_list; l; l = g_slist_delete_link(l, l))
  {
    struct icd_scan_srv_provider *provider =
        (struct icd_scan_srv_provider *)l->data;

    if (provider)
    {
      g_free(provider->service_type);
      g_free(provider->service_name);
      g_free(provider->service_id);
    }

    g_free(provider);
  }

  g_free(cache_entry->network_type);
  g_free(cache_entry->network_name);
  g_free(cache_entry->network_id);
  g_free(cache_entry->station_id);
  g_free(cache_entry);
}

/**
 * @brief Send the cache entry to the listener if the network type matches
 *
 * @param srv_provider send only this service provider to the listener if set;
 * send all network and service provider entries if NULL
 * @param cache_entry the cache entry
 * @param listener the listener
 * @param status the status of the supplied cache entry
 *
 * @return TRUE if the type matched and listener was updated; FALSE otherwise
 *
 */
static gboolean
icd_scan_listener_send_entry(struct icd_scan_srv_provider *srv_provider,
                             struct icd_scan_cache *cache_entry,
                             struct icd_scan_listener *listener,
                             enum icd_scan_status status)
{
  if (!cache_entry)
  {
    ILOG_ERR("scan cannot send NULL cache_entry, because nw type unknown");
    return FALSE;
  }

  if (listener->type &&
      strncmp(listener->type, cache_entry->network_type,
              strlen(listener->type)))
  {
    return FALSE;
  }

  if (status == ICD_SCAN_COMPLETE)
    listener->cb(ICD_SCAN_COMPLETE, 0, cache_entry, listener->user_data);
  else if (srv_provider)
  {
    ILOG_DEBUG("sending %s nw %s/%0x/%s srv %s/%0x/%s",
               icd_scan_status_names[status],
               cache_entry->network_type,
               cache_entry->network_attrs,
               cache_entry->network_id,
               srv_provider->service_type,
               srv_provider->service_attrs,
               srv_provider->service_id);
    listener->cb(status, srv_provider, cache_entry, listener->user_data);
  }
  else
  {
    GSList *l;

    if (!(cache_entry->network_attrs & ICD_NW_ATTR_SRV_PROVIDER))
    {
      listener->cb(status, NULL, cache_entry, listener->user_data);
      ILOG_DEBUG("sending %s nw %s/%0x/%s srv -/-/-",
                 icd_scan_status_names[status],
                 cache_entry->network_type,
                 cache_entry->network_attrs,
                 cache_entry->network_id);
    }

    for (l = cache_entry->srv_provider_list; l; l = l->next)
    {
      struct icd_scan_srv_provider *provider =
          (struct icd_scan_srv_provider *)l->data;

      if (provider)
      {
        ILOG_DEBUG("sending %s nw %s/%0x/%s srv %s/%0x/%s",
                   icd_scan_status_names[status],
                   cache_entry->network_type,
                   cache_entry->network_attrs,
                   cache_entry->network_id,
                   provider->service_type,
                   provider->service_attrs,
                   provider->service_id);
        listener->cb(status, provider, cache_entry, listener->user_data);
      }
    }
  }

  return TRUE;
}

/**
 * @brief Check for elements, return immediately on first element found
 *
 * @param key the network_id, not used
 * @param value #the icd_scan_cache_list
 * @param user_data not used
 *
 * @return TRUE on first non-NULL element found
 *
 */
static gboolean
icd_scan_cache_element_check(gpointer key,
                             struct icd_scan_cache_list *scan_cache_list,
                             gpointer user_data)
{
  GSList *cache_list;
  gboolean rv = FALSE;

  if (scan_cache_list && (cache_list = scan_cache_list->cache_list))
  {
    if (cache_list->data)
      rv = TRUE;
  }

  ILOG_DEBUG("scan cache contains %d elements", rv ? 1 : 0);

  return rv;
}

/**
 * @brief Check wheter a scan cache has any elements
 *
 * @param module network module
 *
 * @return TRUE if there are elements, FALSE otherwise
 *
 */
static gboolean
icd_scan_cache_has_elements(struct icd_network_module *module)
{
  int user_data = 0;

  return !!g_hash_table_find(module->scan_cache_table,
                             (GHRFunc)icd_scan_cache_element_check, &user_data);
}

/**
 * @brief Check if there are any listeners that want scan results
 *
 * @param module the network module
 *
 * @return TRUE if there are listeners, FALSE otherwise
 *
 */
static gboolean
icd_scan_listener_exist(struct icd_network_module *module)
{
  return module->scan_listener_list != NULL;
}

/**
 * @brief Notify each matching listener about the change in the cache entry
 *
 * @param module the network module
 * @param srv_provider NULL or the specific service provider entry that got
 * updated; if non-NULL only this service provider associated with
 * the cache_entry will be sent to the listeners
 * @param cache_entry corresponding cache entry that got updated
 * @param status status of the notification
 *
 */
void
icd_scan_listener_notify(struct icd_network_module *module,
                         struct icd_scan_srv_provider *srv_provider,
                         struct icd_scan_cache *cache_entry,
                         enum icd_scan_status status)
{
  GSList *l;

  for (l = module->scan_listener_list; l; l = l->next)
  {
    icd_scan_listener_send_entry(srv_provider, cache_entry,
                                 (struct icd_scan_listener *)l->data, status);
  }
}
