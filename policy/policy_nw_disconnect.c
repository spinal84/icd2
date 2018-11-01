#include <gconf/gconf-client.h>
#include <osso-ic-gconf.h>

#include "policy_api.h"
#include "icd_log.h"

#define POLICY_NW_DISCONNECT_CANCELS_ALWAYS_ONLINE_GCONF_PATH \
	ICD_GCONF_SETTINGS "/policy/policy_nw_disconnect/cancel_always_online"
#define POLICY_NW_DISCONNECT_USER_REFCOUNT_GCONF_PATH \
	ICD_GCONF_SETTINGS "/policy/policy_nw_disconnect/user_refcount"

static gboolean
policy_nw_disconnect_cancel_always_online()
{
  GError *error = NULL;
  GConfClient *gconf = gconf_client_get_default();
  GConfValue *val = gconf_client_get(
      gconf, POLICY_NW_DISCONNECT_CANCELS_ALWAYS_ONLINE_GCONF_PATH, &error);
  g_object_unref(gconf);

  if (G_VALUE_HOLDS_BOOLEAN(val) && !error)
  {
    gboolean always_online = gconf_value_get_bool(val);
    gconf_value_free(val);
    return always_online;
  }
  else if (!error)
    ILOG_DEBUG("policy nw disconnect cancel always online boolean is not set");
  else
  {
    ILOG_DEBUG("policy nw disconnect cancel always online is not set, "
	       "error '%s'", error->message);
    g_error_free(error);
  }

  if (val)
    gconf_value_free(val);

  return FALSE;
}

static void
policy_nw_disconnect_unset_always_online(void)
{
  GConfClient *gconf = gconf_client_get_default();
  ILOG_DEBUG("policy nw disconnect disabling always online search interval");
  gconf_client_set_int(gconf, ICD_GCONF_NETWORK_SEARCH_INTERVAL, 0, NULL);
  g_object_unref(gconf);
}

static gboolean
policy_nw_disconnect_user_refcount(void)
{
  GError *error = NULL;
  GConfClient *gconf = gconf_client_get_default();
  GConfValue *val = gconf_client_get(
      gconf, POLICY_NW_DISCONNECT_USER_REFCOUNT_GCONF_PATH, &error);
  g_object_unref(gconf);

  if (G_VALUE_HOLDS_BOOLEAN(val) && !error)
  {
    gboolean user_refcount = gconf_value_get_bool(val);
    gconf_value_free(val);
    return user_refcount;
  }
  else if (!error)
    ILOG_DEBUG("policy nw disconnect refcounting boolean is not set");
  else
  {
    ILOG_DEBUG("policy nw disconnect refcounting is not set, error '%s'",
	       error->message);
    g_error_free(error);
  }

  if (val)
    gconf_value_free(val);

  return FALSE;
}

static enum icd_policy_status
policy_nw_disconnect(struct icd_policy_request *network,
		     gint reference_count,
		     GSList *existing_connections,
		     gpointer *private)
{
  if (!reference_count)
  {
    if (policy_nw_disconnect_user_refcount())
    {
      ILOG_INFO("policy nw disconnect reference counting turned on, "
		"disconnecting since no apps active");
      return ICD_POLICY_ACCEPTED;
    }
  }

  if (reference_count >= 0)
  {
    ILOG_INFO("policy nw disconnect reference count %d, not disconnecting",
              reference_count);
    return ICD_POLICY_REJECTED;
  }

  ILOG_INFO("policy nw disconnect reference count %d, disconnect from UI",
            reference_count);

  if (policy_nw_disconnect_cancel_always_online())
    policy_nw_disconnect_unset_always_online();

  return ICD_POLICY_ACCEPTED;
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
  policy_api->disconnect = policy_nw_disconnect;
}
