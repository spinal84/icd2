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
 * @brief Helper function for comparing two strings where a NULL string is equal
 * to another NULL string
 *
 * @param a string A
 * @param b string B
 *
 * @return TRUE if equal, FALSE if unequal
 *
 */
inline static gboolean
string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

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
 * @param value the #icd_scan_cache_list
 * @param user_data not used
 *
 * @return TRUE on first non-NULL element found
 *
 */
static gboolean
icd_scan_cache_element_check(gpointer key,
                             gpointer value,
                             gpointer user_data)
{
  struct icd_scan_cache_list *scan_cache_list =
      (struct icd_scan_cache_list *)value;
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

/**
 * @brief  Hash table callback for removing an entry. Note that this function is
 * also called outside of hash, so care should be taken when dealing with the
 * hash (that is why list_entry is not deleted inside this function).
 *
 * @param key the network_id
 * @param value the icd_scan_cache_list struct
 * @param user_data expiration time
 *
 * @return TRUE when all networks for the network_id have been expired and the
 * hash table element can be removed; FALSE otherwise
 *
 */
static gboolean
icd_scan_expire_network(gpointer key, gpointer value, gpointer user_data)
{
  struct icd_scan_cache_list *scan_cache_list =
      (struct icd_scan_cache_list *)value;
  struct icd_scan_expire_network_data *expire_network_data =
      (struct icd_scan_expire_network_data *)user_data;
  gchar *network_id = (gchar *)key;
  GSList *l = scan_cache_list->cache_list;
  int expired = 0;
  int entries = 0;

  while (l)
  {
    struct icd_scan_cache *cache_entry = (struct icd_scan_cache *)l->data;
    GSList *next = l->next;

    if (cache_entry)
    {
      if (cache_entry->last_seen <= expire_network_data->expire)
      {
        icd_scan_listener_notify(
              expire_network_data->module, NULL, cache_entry, ICD_SCAN_EXPIRE);
        icd_scan_cache_entry_free(cache_entry);
        ++expired;
      }
    }
    else
      ILOG_ERR("NULL cache entry in network '%s'", network_id);

    scan_cache_list->cache_list =
        g_slist_delete_link(scan_cache_list->cache_list, l);

    l = next;
    entries++;
  }

  if (scan_cache_list->cache_list)
  {
    if (expired)
    {
      ILOG_DEBUG("network id '%s' expired %d/%d entries", network_id, expired,
                 entries);
    }
    return FALSE;
  }

  ILOG_DEBUG("network id '%s' all entries expired", network_id);
  return TRUE;
}


/**
 * @brief Hash table callback for removing an entry, this version is only called
 * from hash remove func.
 *
 * @param key the network_id
 * @param value the icd_scan_cache_list struct
 * @param user_data expiration time
 *
 * @return TRUE when all networks for the network_id have been expired and the
 * hash table element can be removed; FALSE otherwise
 *
 */
static gboolean
icd_scan_expire_network_for_hash(gpointer key, gpointer value,
                                 gpointer user_data)
{
  if (icd_scan_expire_network(key, value, user_data))
  {
    g_free(value);
    return TRUE;
  }

  return FALSE;
}

/**
 * @brief  Cache expiry function
 *
 * @param data cache timeout data
 *
 * @return FALSE to remove the timeout
 *
 */
static gboolean
icd_scan_cache_expire(gpointer data)
{
  struct icd_scan_cache_timeout *scan_cache_timeout;

  scan_cache_timeout = (struct icd_scan_cache_timeout *)data;

  if (scan_cache_timeout->module->scan_progress)
    ILOG_DEBUG("deferred scan cache expiration for '%s' due to new scan",
               scan_cache_timeout->module->name);
  else
  {
    struct icd_scan_expire_network_data user_data;

    user_data.module = scan_cache_timeout->module;
    user_data.expire = time(0) - scan_cache_timeout->module->nw.search_lifetime;

    g_hash_table_foreach_remove(scan_cache_timeout->module->scan_cache_table,
                                (GHRFunc)icd_scan_expire_network_for_hash,
                                &user_data);
  }

  scan_cache_timeout->module->scan_timeout_list =
      g_slist_remove(scan_cache_timeout->module->scan_timeout_list,
                     scan_cache_timeout);

  g_free(scan_cache_timeout);

  return FALSE;
}

struct icd_scan_cache_list *
icd_scan_cache_list_lookup(struct icd_network_module *module,
                           const gchar *network_id)
{
  if (!module || !module->scan_cache_table)
    return NULL;

  return (struct icd_scan_cache_list *)
      g_hash_table_lookup(module->scan_cache_table, network_id);
}

static gboolean
icd_scan_cache_remove_iap_for_module(struct icd_network_module *module,
                                     gpointer user_data)
{
  struct icd_scan_cache_list *scan_cache_list;
  GSList *net_type;

  scan_cache_list = icd_scan_cache_list_lookup(module,
                                               (const gchar *)user_data);

  if (!scan_cache_list)
    return TRUE;

  for (net_type = module->network_types; net_type; net_type = net_type->next)
  {
    GSList *cache_list = scan_cache_list->cache_list;
    const gchar *network_type = (const gchar *)net_type->data;
    GSList *next;

    while (cache_list)
    {
      struct icd_scan_cache *cache = (struct icd_scan_cache *)cache_list->data;
      next = cache_list->next;

      if (cache && cache->network_attrs & ICD_NW_ATTR_IAPNAME &&
          string_equal(cache->network_type, network_type))
      {
        ILOG_DEBUG("removing %s, name=%s, attrs=0x%x, type=%s",
                   cache->network_id,
                   cache->network_name,
                   cache->network_attrs,
                   cache->network_type);

        icd_scan_listener_notify(module, NULL, cache, ICD_SCAN_EXPIRE);
        icd_scan_cache_entry_free(cache);
        scan_cache_list->cache_list =
            g_slist_delete_link(scan_cache_list->cache_list, cache_list);

      }

      cache_list = next;
    }
  }

  return TRUE;
}

void
icd_scan_cache_remove_iap(gchar *iap_name)
{
  icd_network_api_foreach_module(icd_context_get(),
                                 icd_scan_cache_remove_iap_for_module,
                                 iap_name);
}

/**
 * @brief Remove scan cache from scan list, the removed entry does not call
 * listener.
 *
 * @param scan_cache_list the icd_scan_cache_list struct
 * @param network_id network identifier
 * @param network_type the network type
 * @param network_attrs network attributes
 *
 * @return TRUE if scan entry was removed; FALSE otherwise
 *
 */
gboolean
icd_scan_cache_entry_remove(struct icd_scan_cache_list *scan_cache_list,
                            const gchar *network_id,
                            const gchar *network_type,
                            const guint network_attrs)
{
  GSList *l = scan_cache_list->cache_list;
  gint entries = 0;

  while (l)
  {
    struct icd_scan_cache *cache = (struct icd_scan_cache *)l->data;
    GSList *next = l->next;

    if (cache && cache->network_attrs == network_attrs &&
        string_equal(cache->network_type, network_type))
    {
      GSList *tmp;

      icd_scan_cache_entry_free(cache);
      tmp = g_slist_delete_link(scan_cache_list->cache_list, l);
      entries++;
      l = next;
      scan_cache_list->cache_list = tmp;
    }

    l = next;
  }

  if (!scan_cache_list->cache_list)
    ILOG_DEBUG("network id '%s' all entries (%d) removed", network_id, entries);

  return !!entries;
}