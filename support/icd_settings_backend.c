#include "icd_settings_backend.h"

gboolean
icd_settings_add_handle (struct icd_settings *settings,
                         icd_settings_handle handle)
{
  if (!handle)
    return FALSE;

  if (!handle->nw.network_id)
    return FALSE;

  g_hash_table_insert(
      settings->network_id, handle->nw.network_id,
      g_slist_prepend(g_hash_table_lookup(settings->network_id,
                                          handle->nw.network_id), handle));

  return TRUE;
}
