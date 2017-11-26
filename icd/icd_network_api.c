#include <string.h>
#include <gconf/gconf-client.h>
#include <osso-ic-dbus.h>
#include "icd_log.h"
#include "icd_context.h"
#include "icd_plugin.h"
#include "icd_scan.h"
#include "icd_srv_provider.h"
#include "icd_iap.h"
#include "icd_network_api.h"
#include "icd_type_modules.h"
#include "icd_status.h"
#include "config.h"
#include "icd_version.h"

/**
 * @brief make icd_scan use the module iteration function
 *
 * @param icd_ctx icd context
 * @param foreach_fn the function to call for each module
 * @param user_data user data to pass to the function
 *
 * @return a pointer to the module if the iteration function returns FALSE; NULL
 * otherwise
 *
 */
struct icd_network_module *
icd_network_api_foreach_module(struct icd_context *icd_ctx,
                               icd_network_api_foreach_module_fn foreach_fn,
                               gpointer user_data)
{
  GSList *l;

  if (!icd_ctx || !foreach_fn)
  {
    ILOG_ERR("icd_ctx or foreach_fn cannot be NULL");
    return NULL;
  }

  for (l = icd_ctx->nw_module_list; l; l = l->next)
  {
    struct icd_network_module *module = (struct icd_network_module *)l->data;

    if (l->data)
    {
      if (!foreach_fn(module, user_data))
        return module;
    }
    else
      ILOG_WARN("Module list has NULL module data");
  }

  return NULL;
}

/** pid and exit value structure */
struct pid_notify {
  /** process id */
  pid_t pid;
  /** exit value  */
  gint exit_value;
};

/**
 * @brief Find the network module that is watching a child process exit
 *
 * @param module the network module to examine
 * @param user_data the #pid_notify structure
 *
 * @return TRUE to continue searching, FALSE to exit iteration and return a
 * pointer to the module
 *
 */
static gboolean
icd_network_api_foreach_module_pid(struct icd_network_module *module,
                                   gpointer user_data)
{
  struct pid_notify *notify = (struct pid_notify *)user_data;
  GSList *l;
  struct pid_notify *candidate;

  for (l = module->pid_list; l; l = l->next)
  {
    candidate = (struct pid_notify *)l->data;

    if (candidate->pid == notify->pid)
      break;
  }

  if (!l)
    return TRUE;

  g_free(candidate);
  module->pid_list = g_slist_delete_link(module->pid_list, l);

  if (module->nw.child_exit)
  {
    ILOG_INFO("module '%s' notified for pid %d", module->name, notify->pid);
    module->nw.child_exit(notify->pid, notify->exit_value, &module->nw.private);
  }
  else
  {
    ILOG_WARN("module '%s' cannot be notified about pid %d as child_exit is NULL",
              module->name, notify->pid);
  }

  return FALSE;
}

/**
 * @brief Notify a network module that its child process has exited
 *
 * @param icd_ctx the context
 * @param pid the process id
 * @param exit_value exit value
 *
 * @return TRUE if the process id was in use by the network api; FALSE if not
 *
 */
gboolean
icd_network_api_notify_pid(struct icd_context *icd_ctx, const pid_t pid,
                           const gint exit_value)
{
  struct pid_notify notify;
  notify.pid = pid;
  notify.exit_value = exit_value;

  return icd_network_api_foreach_module(icd_ctx,
                                        icd_network_api_foreach_module_pid,
                                        &notify) != 0;
}

/**
 * @brief Set ICd to watch a child pid
 *
 * @param pid process id
 * @param watch_cb_token the watch callback token given on initialization
 *
 */
static void
icd_network_api_watch_pid(const pid_t pid, gpointer watch_cb_token)
{
  struct icd_network_module *module;
  pid_t *ppid;

  module = (struct icd_network_module *)watch_cb_token;

  if (module)
  {
    ppid = g_new(pid_t, 1);
    *ppid = pid;
    module->pid_list = g_slist_prepend(module->pid_list, ppid);

    ILOG_DEBUG("added pid %ld to module '%s'", (long)pid, module->name);
  }
  else
    ILOG_ERR("module NULL while submitting child pid");
}

/**
 * @brief  Status of the network has changed while the network has been
 * connected
 *
 * @param network_type the type of the IAP returned
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 *
 */
static void
icd_network_api_status_update(gchar *network_type, guint network_attrs,
                              gchar *network_id)
{
  struct icd_iap *iap = icd_iap_find(network_type, network_attrs, network_id);

  if (!iap)
  {
    ILOG_WARN("status update requested for %s/%0x/%s, but no matching IAP",
              network_type, network_attrs, network_id);
    return;
  }

  if (iap->state == ICD_IAP_STATE_CONNECTED)
  {
    ILOG_INFO("status update requested for IAP %p, %s/%0x/%s", iap,
              network_type, network_attrs, network_id);
    icd_status_connected(iap, NULL, NULL);
  }
  else
  {
    ILOG_WARN("status update requested for %s/%0x/%s, but IAP not in state ICD_IAP_STATE_CONNECTED",
              network_type, network_attrs, network_id);
  }
}

/**
 * @brief Function for closing down a connection by request of a network module
 *
 * @param status reason for closing; ICD_NW_RESTART if the IAP needs to be
 * restarted, success or error will both close the network connection
 * @param err_str NULL if the network was disconnected normally or any
 * ICD_DBUS_ERROR_* from osso-ic-dbus.h on error
 * @param network_type the type of the IAP returned
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 *
 */
void
icd_network_api_close(enum icd_nw_status status, const gchar *err_str,
                      const gchar *network_type, const guint network_attrs,
                      const gchar *network_id)
{
  struct icd_iap *iap =icd_iap_find(network_type, network_attrs, network_id);

  if (!iap)
  {
    ILOG_WARN("disconnect requested for %s/%0x/%s, but no matching IAP",
              network_type, network_attrs, network_id);
    return;
  }

  if (iap->state >= ICD_IAP_STATE_CONNECTED_DOWN &&
      iap->state <= ICD_IAP_STATE_SCRIPT_POST_DOWN)
  {
    ILOG_INFO("close requested for IAP %p ignored, already in state %s", iap,
              icd_iap_state_names[iap->state]);
    return;
  }

  ILOG_INFO("close requested for IAP %p, %s/%0x/%s", iap, network_type,
            network_attrs, network_id);
  icd_status_disconnect(iap, 0, err_str);

  switch (status)
  {
    case ICD_NW_RESTART:
      icd_iap_restart(iap, ICD_NW_LAYER_ALL);
      break;
    case ICD_NW_RESTART_IP:
      icd_iap_restart(iap, ICD_NW_LAYER_IP);
      break;
    case ICD_NW_RESTART_LINK_POST:
      icd_iap_restart(iap, ICD_NW_LAYER_LINK_POST);
      break;
    case ICD_NW_RESTART_LINK:
      icd_iap_restart(iap, ICD_NW_LAYER_LINK);
      break;
    default:
    {
      const char *err;

      if (status == ICD_NW_ERROR && err_str)
        err = err_str;
      else
        err = ICD_DBUS_ERROR_NETWORK_ERROR;

      icd_iap_disconnect(iap, err);
      break;
    }
  }
}

static void
icd_network_api_renew(enum icd_nw_layer renew_layer, const gchar *network_type,
                      const guint network_attrs, const gchar *network_id)
{
  struct icd_iap *iap = icd_iap_find(network_type, network_attrs, network_id);

  if (!iap)
  {
    ILOG_WARN("network renew requested for %s/%0x/%s, but no matching IAP",
              network_type, network_attrs, network_id);
  }

  ILOG_DEBUG("network renew for iap %p %s/%0x/%s layer %d requested", iap,
             network_type, network_attrs, network_id, renew_layer);

  switch (iap->state)
  {
    case ICD_IAP_STATE_DISCONNECTED:
    case ICD_IAP_STATE_SCRIPT_PRE_UP:
      ILOG_WARN("cannot renew anything in state %s",
                icd_iap_state_names[iap->state]);
      return;
    case ICD_IAP_STATE_LINK_UP:
      if (renew_layer == ICD_NW_LAYER_NONE ||
          renew_layer == ICD_NW_LAYER_LINK || renew_layer == ICD_NW_LAYER_ALL)
      {
        icd_iap_restart(iap, renew_layer);
        return;
      }

      break;
    case ICD_IAP_STATE_LINK_POST_UP:
      if (renew_layer == ICD_NW_LAYER_LINK_POST)
        icd_iap_restart(iap, renew_layer);
      else if (renew_layer == ICD_NW_LAYER_NONE ||
               renew_layer == ICD_NW_LAYER_LINK ||
               renew_layer == ICD_NW_LAYER_ALL)
      {
        icd_iap_renew(iap, renew_layer);
      }
      else
        break;

      return;
    case ICD_IAP_STATE_IP_UP:
      if (renew_layer == ICD_NW_LAYER_IP)
        icd_iap_restart(iap, renew_layer);
      else if (renew_layer != ICD_NW_LAYER_SERVICE)
        icd_iap_renew(iap, renew_layer);
      else
          break;

      return;
    case ICD_IAP_STATE_SRV_UP:
      if (renew_layer != ICD_NW_LAYER_SERVICE)
        icd_iap_renew(iap, renew_layer);
      else
        icd_iap_restart(iap, renew_layer);

      return;
    case ICD_IAP_STATE_SCRIPT_POST_UP:
    case ICD_IAP_STATE_SAVING:
    case ICD_IAP_STATE_CONNECTED:
      icd_iap_renew(iap, renew_layer);
      return;
    default:
      ILOG_DEBUG("no need to renew anything in state %s while going down",
                 icd_iap_state_names[iap->state]);
      return;
  }

  ILOG_DEBUG("in state %s, no need to renew anything",
             icd_iap_state_names[iap->state]);
}
