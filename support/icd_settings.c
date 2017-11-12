#include <string.h>

#include "icd_settings_backend.h"
#include "icd_backend_gconf.h"

static struct icd_settings *icd_settings = NULL;

static struct icd_settings **
icd_settings_get()
{
  if (!icd_settings)
  {
    icd_settings = g_new0(struct icd_settings, 1);
    icd_settings->network_id = g_hash_table_new(g_str_hash, g_str_equal);
    icd_backend_gconf_init(icd_settings);
  }
  return &icd_settings;
}

gboolean
icd_settings_init(void)
{
  return !!icd_settings_get();
}

static gboolean
string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

icd_settings_handle
icd_settings_get_by_network(const gchar *network_type,
                            const guint network_attrs, const gchar *network_id)
{
  struct icd_settings **settings = icd_settings_get();
  GSList *l;

  if (!network_id)
    return NULL;

  for (l = g_hash_table_lookup((*settings)->network_id, network_id); l;
                               l = l->next)
  {
    icd_settings_handle_t *handle = l->data;

    if (handle->nw.network_attrs == network_attrs &&
        string_equal(network_type, handle->nw.network_type))
    {
      return handle;
    }
  }

  return
      icd_backend_gconf_get_by_network(network_type, network_attrs,network_id);
}

gboolean
icd_settings_delete(icd_settings_handle handle)
{
  struct icd_settings **settings = icd_settings_get();
  GSList *l;

  if (!handle || !handle->nw.network_id)
    return FALSE;

  for (l = g_hash_table_lookup((*settings)->network_id, handle->nw.network_id);
       l; l = l->next)
  {
    icd_settings_handle candidate = l->data;

    if (candidate->nw.network_attrs == handle->nw.network_attrs &&
        string_equal(candidate->nw.network_type, handle->nw.network_type))
    {
      l = g_slist_delete_link(l, l);

      if (l)
        g_hash_table_insert((*settings)->network_id, handle->nw.network_id, l);
      else
        g_hash_table_remove((*settings)->network_id, handle->nw.network_id);

      break;
    }

  }

  icd_backend_gconf_delete(handle);

  return TRUE;
}
