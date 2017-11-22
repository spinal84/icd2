#include <string.h>
#include <time.h>
#include <gconf/gconf-client.h>
#include <glib.h>
#include <osso-ic-gconf.h>
#include <osso-ic-dbus.h>
#include "icd_plugin.h"
#include "srv_provider_api.h"
#include "icd_srv_provider.h"
#include "icd_log.h"
#include "icd_status.h"
#include "icd_network_priority.h"
#include "icd_version.h"

/** pid and exit value structure */
struct pid_notify {
  /** process id */
  pid_t pid;
  /** exit value  */
  gint exit_value;
};

static gboolean
icd_srv_provider_foreach_module_pid(struct icd_srv_module *srv_module,
                                    gpointer user_data)
{
  GSList *l;
  struct pid_notify *notify = (struct pid_notify *)user_data;

  for (l = srv_module->pid_list; l; l = l->next)
  {
    pid_t *pid = (pid_t *)l->data;

    if (pid && *pid == notify->pid)
    {
      g_free(pid);
      srv_module->pid_list = g_slist_delete_link(srv_module->pid_list, l);

      if (srv_module->srv.child_exit)
      {
        ILOG_INFO("srv module '%s' notified for pid %d", srv_module->name,
                  notify->pid);
        srv_module->srv.child_exit(notify->pid, notify->exit_value,
                                   &srv_module->srv.private);
      }
      else
      {
        ILOG_WARN("module '%s' cannot be notified about pid %d as child_exit is NULL",
                  srv_module->name, notify->pid);
      }

      return FALSE;
    }
  }

  return TRUE;
}

struct icd_srv_module *
icd_srv_provider_foreach_module(struct icd_context *icd_ctx,
                                icd_srv_provider_foreach_module_fn foreach_fn,
                                gpointer user_data)
{
  GSList *l;

  if (!icd_ctx || !foreach_fn)
  {
    ILOG_ERR("icd_ctx or foreach_fn cannot be NULL");
    return NULL;
  }

  for (l = icd_ctx->srv_module_list; l; l = l->next)
  {
    struct icd_srv_module *module = (struct icd_srv_module *)l->data;

    if (module)
    {
      if (!foreach_fn(module, user_data))
        return module;
    }
    else
      ILOG_WARN("srv module list has NULL module data");
  }

  return NULL;
}

gboolean
icd_srv_provider_notify_pid(struct icd_context *icd_ctx, const pid_t pid,
                            const gint exit_value)
{
  struct pid_notify notify;

  notify.pid = pid;
  notify.exit_value = exit_value;

  return icd_srv_provider_foreach_module(icd_ctx,
                                         icd_srv_provider_foreach_module_pid,
                                         &notify) != NULL;
}

static void
icd_srv_provider_disconnect_cb(enum icd_srv_status status,
                               gpointer disconnect_cb_token)
{
  struct icd_iap *iap = (struct icd_iap *)disconnect_cb_token;


  if (iap)
  {
    icd_srv_provider_disconnect_cb_fn fn =
        (icd_srv_provider_disconnect_cb_fn)iap->srv_disconnect_cb;

    if (fn)
      fn(status, iap->srv_disconnect_cb_user_data);

    iap->srv_disconnect_cb_user_data = NULL;
    iap->srv_disconnect_cb = NULL;
  }
  else
    ILOG_ERR("srv provider disconnect cb returned NULL iap");
}

gboolean
icd_srv_provider_disconnect(struct icd_iap *iap,
                            icd_srv_provider_disconnect_cb_fn cb,
                            gpointer user_data)
{
  struct icd_context *icd_ctx;
  struct icd_srv_module *module;

  if (!cb)
  {
    ILOG_ERR("srv provider disconnect cb cannot be NULL");
    return FALSE;
  }

  icd_ctx = icd_context_get();

  if (!iap->connection.service_type || !iap->connection.service_id)
  {
    ILOG_DEBUG("no service module for iap %p", iap);
    return FALSE;
  }

  if (iap->srv_disconnect_cb)
  {
    ILOG_INFO("srv provider disconnect already in progress for iap %p", iap);
    return FALSE;
  }

  module = (struct icd_srv_module *)g_hash_table_lookup(
        icd_ctx->srv_type_to_srv_module, iap->connection.service_type);

  if (!module)
  {
    ILOG_ERR("srv type '%s' unknown", iap->connection.service_type);
    return FALSE;
  }

  if (!module->srv.disconnect)
    return FALSE;

  iap->srv_disconnect_cb = cb;
  iap->srv_disconnect_cb_user_data = user_data;

  module->srv.disconnect(iap->connection.service_type,
                         iap->connection.service_attrs,
                         iap->connection.service_id,
                         iap->connection.network_type,
                         iap->connection.network_attrs,
                         iap->connection.network_id,
                         iap->interface_name,
                         icd_srv_provider_disconnect_cb,
                         iap, &module->srv.private);

  return TRUE;
}
