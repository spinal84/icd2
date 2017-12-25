#include <gconf/gconf-client.h>
#include <osso-ic-gconf.h>

#include "policy_api.h"
#include "icd_log.h"

#define ICD_POLICY_RESTART_COUNT_DEFAULT 25
#define ICD_POLICY_RESTART_COUNT_MAX 40

#define ICD_POLICY_RESTART_COUNT ICD_GCONF_SETTINGS "/policy/policy_iap_restart/restart_count"

static enum icd_policy_status
icd_policy_restart_restart(struct icd_policy_request *network,
                           guint restart_count, gpointer *privatx)
{
  GConfClient *gconf = gconf_client_get_default();
  GConfValue *val;
  unsigned int restart_count_gconf;
  GError *error = NULL;

  val = gconf_client_get(gconf, ICD_POLICY_RESTART_COUNT, &error);
  g_object_unref(gconf);

  if (!G_VALUE_HOLDS_INT(val) || error)
  {
    ILOG_DEBUG("policy restart has no value set, using default %d",
               ICD_POLICY_RESTART_COUNT_DEFAULT);

    if (error)
      g_error_free(error);

    if (val)
      gconf_value_free(val);

    restart_count_gconf = ICD_POLICY_RESTART_COUNT_DEFAULT;
  }
  else
  {
    restart_count_gconf = gconf_value_get_int(val);
    gconf_value_free(val);

    if (restart_count_gconf > ICD_POLICY_RESTART_COUNT_MAX)
    {
      ILOG_WARN("policy restart value %d not in range %d-%d, reset to %d",
                restart_count_gconf, 0, ICD_POLICY_RESTART_COUNT_MAX,
                ICD_POLICY_RESTART_COUNT_DEFAULT);

      restart_count_gconf = ICD_POLICY_RESTART_COUNT_DEFAULT;
    }
  }

  if (restart_count <= restart_count_gconf)
    return ICD_POLICY_ACCEPTED;

  return ICD_POLICY_REJECTED;
}

void
icd_policy_init(struct icd_policy_api *policy_api,
                icd_policy_nw_add_fn add_network,
                icd_policy_request_merge_fn merge_requests,
                icd_policy_request_make_new_fn make_request,
                icd_policy_scan_start_fn scan_start,
                icd_policy_scan_stop_fn scan_stop,
                icd_policy_nw_close_fn nw_close,
                icd_policy_network_priority_fn priority,
                icd_policy_service_module_check_fn srv_check)
{
  policy_api->restart = icd_policy_restart_restart;
}
