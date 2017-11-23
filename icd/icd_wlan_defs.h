#ifndef ICD_WLAN_DEFS
#define ICD_WLAN_DEFS

#include <glib.h>

/** wlan infrastructure mode */
#define WLAN_TYPE_INFRA   "WLAN_INFRA"

/** wlan ad-hoc mode */
#define WLAN_TYPE_ADHOC   "WLAN_ADHOC"

/** open wlan network setting in network attributes */
#define WLAN_SECURITY_OPEN         0x1 << 3

/** wep wlan encryption in netowork attributes */
#define WLAN_SECURITY_WEP          0x2 << 3

/** wpa psk wlan encryption in network attributes */
#define WLAN_SECURITY_WPA_PSK      0x4 << 3

guint icd_wlan_defs_get_secmode (const gchar *iap_name);

gboolean icd_wlan_defs_is_wlan (const gchar *network_type);

#endif
