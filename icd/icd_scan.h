#ifndef ICD_SCAN_H
#define ICD_SCAN_H

#include <glib.h>

#include "network_api.h"
#include "dbus_api.h"

struct icd_scan_cache_list {
  GSList *cache_list;
};

struct icd_scan_srv_provider {
  gchar *service_type;
  gchar *service_name;
  guint service_attrs;
  gchar *service_id;
  gint service_priority;
};

struct icd_scan_cache {
  guint last_seen;

  gchar *network_type;
  gchar *network_name;
  guint network_attrs;
  gchar *network_id;
  gint network_priority;

  enum icd_nw_levels signal;

  gchar *station_id;
  gint dB;

  GSList *srv_provider_list;
};

struct icd_scan_cache_timeout {
  struct icd_network_module *module;
  guint id;
};

typedef void
(*icd_scan_cb_fn) (enum icd_scan_status status,
                   const struct icd_scan_srv_provider *srv_provider,
                   const struct icd_scan_cache *cache_entry,
                   gpointer user_data);

void icd_scan_cache_entry_free (struct icd_scan_cache *cache_entry);

void icd_scan_cache_entry_add (struct icd_network_module *module,
                               struct icd_scan_cache_list *scan_cache,
                               struct icd_scan_cache *cache_entry);

struct icd_scan_cache_list *
icd_scan_cache_list_lookup (struct icd_network_module *module,
                            const gchar *network_id);

struct icd_scan_cache *
icd_scan_cache_entry_find (struct icd_scan_cache_list *scan_cache_list,
                           const gchar *network_type,
                           const guint network_attrs);

gboolean icd_scan_cache_entry_remove(struct icd_scan_cache_list *scan_cache_list,
                                     const gchar *network_id,
                                     const gchar *network_type,
                                     const guint network_attrs);

void icd_scan_listener_notify (struct icd_network_module *module,
                               struct icd_scan_srv_provider *srv_provider,
                               struct icd_scan_cache *cache_entry,
                               enum icd_scan_status status);

gboolean icd_scan_results_request (const gchar *type,
                                   const guint scope,
                                   icd_scan_cb_fn cb,
                                   gpointer user_data);
gboolean icd_scan_results_unregister (icd_scan_cb_fn cb,
                                      gpointer user_data);
gboolean icd_scan_cache_init (struct icd_network_module *module);
void icd_scan_cache_remove (struct icd_network_module *module);

void icd_scan_cache_remove_iap(gchar *iap_name);

#endif
