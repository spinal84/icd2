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
