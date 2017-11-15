#include "icd_network_api.h"
#include "icd_scan.h"
#include "icd_log.h"

/**
 * scan listener list data
 */
struct icd_scan_listener {
  /** network type */
  gchar *type;
  /** callback */
  icd_scan_cb_fn cb;
  /** callback data */
  gpointer user_data;
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
