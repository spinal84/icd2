#include <string.h>
#include "icd_wlan_defs.h"
#include "icd_gconf.h"

guint
icd_wlan_defs_get_secmode(const gchar *iap_name)
{
  gchar *s;
  guint rv = 0;

  s = icd_gconf_get_iap_string(iap_name, "wlan_security");

  if (!s)
    return 0;

  if (!strcmp(s, "WEP"))
    rv = WLAN_SECURITY_WEP;

  g_free(s);

  return rv;
}

gboolean
icd_wlan_defs_is_wlan(const gchar *network_type)
{
  if ( network_type )
  {
    if (!strcmp(network_type, WLAN_TYPE_INFRA) ||
        !strcmp(network_type, WLAN_TYPE_ADHOC))
    {
      return TRUE;
    }
  }

  return FALSE;
}
