#ifndef ICD_CONTEXT_H
#define ICD_CONTEXT_H

#include <glib.h>

struct icd_context {
  gboolean daemon;
  guint shutting_down;
  GMainLoop *main_loop;

  GSList *policy_module_list;

  GSList *request_list;

  GSList *nw_module_list;
  GHashTable *type_to_module;

  GSList *srv_module_list;
  GHashTable *srv_type_to_srv_module;
  GHashTable *nw_type_to_srv_module;

  guint idle_timer_notify;

  guint iap_deletion_notify;
};

gboolean icd_context_init (void);
struct icd_context *icd_context_get(void);
void icd_context_run(void);
void icd_context_stop(void);
void icd_context_destroy (void);

#endif
