#ifndef ICD_SCAN_H
#define ICD_SCAN_H

#include <glib.h>

#include "network_api.h"
#include "dbus_api.h"

struct icd_scan_cache_list {
  GSList *cache_list;
};

/** service provider data */
struct icd_scan_srv_provider {
  /** service type */
  gchar *service_type;

  /** service level name displayable to the user */
  gchar *service_name;

  /** service attributes */
  guint service_attrs;

  /** service level id */
  gchar *service_id;

  /** service priority inside a service_type */
  gint service_priority;
};

/** cached scanned networks */
struct icd_scan_cache {
  /**  time when the entry was added or updated */
  guint last_seen;

  /** type of network */
  gchar *network_type;

  /** name of the network displayable to user */
  gchar *network_name;

  /** network attributes */
  guint network_attrs;

  /** network id */
  gchar *network_id;

  /** network priority between different network_type */
  gint network_priority;

  /** signal level */
  enum icd_nw_levels signal;

  /** base station MAC address */
  gchar *station_id;

  /* raw signal strength */
  gint dB;

  /** #icd_scan_srv_provider list of service providers for this network */
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
