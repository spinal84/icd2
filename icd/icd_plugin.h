#ifndef ICD_PLUGIN_H
#define ICD_PLUGIN_H

#include <glib.h>

typedef gboolean (*icd_plugin_load_cb_fn) (const gchar* module_name,
                                           void *handle,
                                           gpointer init_function,
                                           gpointer cb_data);

gboolean icd_plugin_load (const char *filename,
                          const char *name,
                          const char *init_name,
                          icd_plugin_load_cb_fn cb,
                          gpointer cb_data);

gboolean icd_plugin_load_all (const char *plugindir,
                              const char *prefix,
                              const char *init_name,
                              icd_plugin_load_cb_fn cb,
                              gpointer cb_data);

gboolean icd_plugin_load_list (const char *plugindir,
                               GSList *plugin_list,
                               const char *init_name,
                               icd_plugin_load_cb_fn cb,
                               gpointer cb_data);

void icd_plugin_unload_module (void *handle);

#endif
