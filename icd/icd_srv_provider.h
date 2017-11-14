#ifndef ICD_SRV_PROVIDER_H
#define ICD_SRV_PROVIDER_H

#include <glib.h>

#include "icd_context.h"
#include "icd_network_api.h"
#include "icd_scan.h"
#include "icd_iap.h"
#include "srv_provider_api.h"

struct icd_srv_module {
  void *handle;
  gchar *name;

  GSList *pid_list;
  struct icd_srv_api srv;

};

typedef gboolean
(*icd_srv_provider_foreach_module_fn) (struct icd_srv_module* module,
                                       gpointer user_data);

struct icd_srv_module *
icd_srv_provider_foreach_module (struct icd_context *icd_ctx,
                                 icd_srv_provider_foreach_module_fn foreach_fn,
                                 gpointer user_data);

typedef void (*icd_srv_provider_connect_cb_fn) (enum icd_srv_status status,
                                                const gchar *err_str,
                                                gpointer user_data);

typedef void (*icd_srv_provider_disconnect_cb_fn) (enum icd_srv_status status,
                                                   gpointer user_data);

gboolean icd_srv_provider_disconnect (struct icd_iap *iap,
                                      icd_srv_provider_disconnect_cb_fn cb,
                                      gpointer user_data);

gboolean icd_srv_provider_has_next (struct icd_iap *iap);

gboolean icd_srv_provider_connect (struct icd_iap *iap,
                                   icd_srv_provider_connect_cb_fn cb,
                                   gpointer user_data);

gboolean icd_srv_provider_identify (struct icd_network_module *nw_module,
                                    struct icd_scan_cache *cache_entry,
                                    enum icd_scan_status status);

gboolean icd_srv_provider_notify_pid (struct icd_context *icd_ctx,
                                      const pid_t pid,
                                      const gint exit_value);

gboolean icd_srv_provider_load_modules (struct icd_context *icd_ctx);

void icd_srv_provider_unload_modules (struct icd_context *icd_ctx);

gboolean icd_srv_provider_check (const gchar *network_type);

#endif
