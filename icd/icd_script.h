#ifndef ICD_SCRIPT_H
#define ICD_SCRIPT_H

#include <sys/types.h>
#include <unistd.h>
#include <glib.h>

#include "icd_iap.h"

typedef void (*icd_script_cb_fn) (const pid_t pid, const gint exit_value,
                                  gpointer user_data);

gboolean icd_script_notify_pid (const pid_t pid, const gint exit_value);

void icd_script_cancel (const pid_t pid);

pid_t icd_script_pre_up (const gchar *iap_id,
                         const gchar *iap_type,
                         const struct icd_iap_env *env,
                         icd_script_cb_fn cb,
                         gpointer user_data);

pid_t icd_script_post_up (const gchar *iface,
                          const gchar *iap_id,
                          const gchar *iap_type,
                          const struct icd_iap_env *env,
                          icd_script_cb_fn cb,
                          gpointer user_data);

pid_t icd_script_pre_down (const gchar *iface,
                           const gchar *iap_id,
                           const gchar *iap_type,
                           const gboolean remove_proxies,
                           const struct icd_iap_env *env,
                           icd_script_cb_fn cb,
                           gpointer user_data);

pid_t icd_script_post_down (const gchar *iface,
                            const gchar *iap_id,
                            const gchar *iap_type,
                            const struct icd_iap_env *env,
                            icd_script_cb_fn cb,
                            gpointer user_data);

void icd_script_add_env_vars (struct icd_iap *iap, gchar **env_vars);

#endif
