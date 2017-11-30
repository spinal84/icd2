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

/** service provider entry for the module name */
#define ICD_SRV_PROVIDER_MODULE_NAME   "/module"

/** service provider entry for supported network types */
#define ICD_SRV_PROVIDER_NETWORK_TYPES   "/network_type"

/** pid and exit value structure */
struct pid_notify {
  /** process id */
  pid_t pid;
  /** exit value  */
  gint exit_value;
};

/** structure for passing data to module initialization callback */
struct icd_srv_provider_cb_data {
  /** icd context */
  struct icd_context *icd_ctx;

  /** supported service type */
  gchar *service_type;

  /** supported network types */
  GSList *network_types;
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

gboolean
icd_srv_provider_check(const gchar *network_type)
{
  struct icd_context *icd_ctx = icd_context_get();

  if (!g_slist_nth_data(icd_ctx->srv_module_list, 0))
    return FALSE;

  if (network_type)
    return !!g_hash_table_lookup(icd_ctx->nw_type_to_srv_module, network_type);

  return TRUE;
}

static void
icd_srv_provider_watch_pid(const pid_t pid, gpointer watch_cb_token)
{
  struct icd_srv_module *module = (struct icd_srv_module *)watch_cb_token;
  pid_t *ppid;

  if (watch_cb_token)
  {
    ppid = g_new0(pid_t, 1);
    *ppid = pid;
    module->pid_list = g_slist_prepend(module->pid_list, ppid);
    ILOG_DEBUG("added pid %d to module '%s'", *ppid, module->name);
  }
  else
    ILOG_ERR("module NULL while submitting srv module child pid");
}

static void
icd_srv_provider_close(enum icd_srv_status status, const gchar *err_str,
                       const gchar *service_type, const guint service_attrs,
                       const gchar *service_id, const gchar *network_type,
                       const guint network_attrs, const gchar *network_id)
{
  struct icd_iap *iap = icd_iap_find(network_type, network_attrs, network_id);

  if (iap)
  {
    ILOG_INFO("srv provider disconnecting IAP %p, srv %s/%0x/%s, nw %s/%0x/%s",
              iap, service_type, service_attrs, service_id, network_type,
              network_attrs, network_id);

    icd_status_disconnect(iap, 0, err_str);

    if (status == ICD_SRV_RESTART)
      icd_iap_restart(iap, ICD_NW_LAYER_ALL);
    else
    {
      if (status == ICD_SRV_ERROR && !err_str)
        err_str = ICD_DBUS_ERROR_NETWORK_ERROR;

      icd_iap_disconnect(iap, err_str);
    }
  }
  else
  {
    ILOG_WARN("disconnect requested for srv %s/%0x/%s, nw %s/%0x/%s but no matching nw",
              service_type, service_attrs,  service_id, network_type,
              network_attrs, network_id);
  }
}

static void
icd_srv_provider_limited_conn(
    const enum icd_srv_limited_conn_status conn_status,
    const gchar *service_type, const guint service_attrs,
    const gchar *service_id, const gchar *network_type,
    const guint network_attrs, const gchar *network_id)
{
  struct icd_iap *iap = icd_iap_find(network_type, network_attrs, network_id);

  if (iap)
  {
    if ( iap->state == ICD_IAP_STATE_SRV_UP )
    {
      gboolean limited_conn = conn_status == ICD_SRV_LIMITED_CONN_ENABLED;

      if (iap->limited_conn != limited_conn)
      {
        iap->limited_conn = limited_conn;
        icd_status_limited_conn(iap, NULL, NULL);
      }
    }
    else
    {
      ILOG_WARN("limited connectivity requested for srv %s/%0x/%s, nw %s/%0x/%s but iap in wrong state (%d)",
                service_type, service_attrs, service_id, network_type,
                network_attrs, network_id, iap->state);
    }
  }
  else
  {
    ILOG_WARN("limited connectivity requested for srv %s/%0x/%s, nw %s/%0x/%s but no matching nw",
              service_type, service_attrs, service_id, network_type,
              network_attrs, network_id);
  }
}

static gboolean
icd_srv_provider_init(const gchar *module_name, void *handle,
                      gpointer init_function, gpointer cb_data)
{
  struct icd_srv_provider_cb_data *data =
      (struct icd_srv_provider_cb_data *)cb_data;
  struct icd_srv_module *module = (struct icd_srv_module *)g_hash_table_lookup(
        data->icd_ctx->srv_type_to_srv_module, data->service_type);
  icd_srv_init_fn init = (icd_srv_init_fn)init_function;
  gboolean rv = FALSE;

  if (!module)
  {
    module = g_new0(struct icd_srv_module, 1);
    module->handle = handle;

    if (init(&module->srv, icd_srv_provider_watch_pid, module,
                      icd_srv_provider_close, icd_srv_provider_limited_conn))
    {
      if (module->srv.version)
      {
        if (module->srv.identify)
        {
          if (module->srv.connect)
          {
            if (icd_version_compare(module->srv.version, "0.54") >= 0)
            {
              GSList *nt = data->network_types;

              module->name = g_strdup(module_name);

              for (nt = data->network_types; nt; nt = nt->next )
              {
                const gchar *network_type = (const gchar *)nt->data;

                if (network_type)
                {
                  GSList *nw_type_to_srv;

                  ILOG_INFO("service provider module %p '%s', network type '%s'",
                            module, module->name, network_type);

                  nw_type_to_srv = (GSList *)g_hash_table_lookup(
                        data->icd_ctx->nw_type_to_srv_module, network_type);

                  g_hash_table_insert(data->icd_ctx->nw_type_to_srv_module,
                                      g_strdup(network_type),
                                      g_slist_prepend(nw_type_to_srv, module));
                }
              }

              data->icd_ctx->srv_module_list =
                  g_slist_prepend(data->icd_ctx->srv_module_list, module);
              rv = TRUE;
            }
            else
            {
              ILOG_ERR("Service module '%s' version %s compiled against API < 0.54, not loading it",
                       module_name, module->srv.version);
            }
          }
          else
          {
            ILOG_ERR("Service module '%s' did not have a connect function",
                     module_name);
          }
        }
        else
        {
          ILOG_ERR("Service module '%s' did not have an identify function",
                   module_name);
        }
      }
      else
        ILOG_ERR("Service module '%s' did not set version", module_name);

      if (!rv)
      {
        if (module->srv.srv_destruct)
          module->srv.srv_destruct(&module->srv.private);

        icd_plugin_unload_module(module->handle);
      }
    }
  }
  else
  {
    ILOG_DEBUG("service provider module %p exists for type '%s'", module,
               data->service_type);
    rv = TRUE;
  }

  if (rv)
  {
    g_hash_table_insert(data->icd_ctx->srv_type_to_srv_module,
                        g_strdup(data->service_type), module);
    ILOG_INFO("service provider module %p '%s' version %s srv type '%s'",
              module, module->name, module->srv.version, data->service_type);
  }
  else
  {
    ILOG_WARN("service module %p '%s' failed to load", module, module_name);
    g_free(module);
  }

  return rv;
}

gboolean
icd_srv_provider_load_modules(struct icd_context *icd_ctx)
{
  GConfClient *gconf = gconf_client_get_default();
  struct icd_srv_provider_cb_data cb_data;
  GSList *dirs;
  GError *err = NULL;
  gboolean rv = FALSE;

  dirs = gconf_client_all_dirs(gconf, ICD_GCONF_SRV_PROVIDERS, &err);

  if (err)
  {
    ILOG_INFO("could not find service provider types: %s", err->message);
    g_clear_error(&err);
    g_object_unref(gconf);
    return FALSE;
  }

  cb_data.icd_ctx = icd_ctx;
  icd_ctx->srv_type_to_srv_module =
      g_hash_table_new_full(g_str_hash,g_str_equal, g_free, NULL);
  icd_ctx->nw_type_to_srv_module =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  while (dirs)
  {
    gchar *dir = (gchar *)dirs->data;

    if (dir)
    {
      GSList *network_types;
      gchar *name;
      gchar *key;
      gchar *filename;
      gchar *service_type = g_strrstr(dir, "/");

      cb_data.service_type = service_type;
      key = g_strconcat(dir, ICD_SRV_PROVIDER_MODULE_NAME, NULL);
      name = gconf_client_get_string(gconf, key, &err);
      g_free(key);

      if (err)
      {
        ILOG_INFO("could not find service provider module name: %s",
                  err->message);
        g_clear_error(&err);
      }

      key = g_strconcat(dir, ICD_SRV_PROVIDER_NETWORK_TYPES, NULL);
      network_types = gconf_client_get_list(gconf, key, GCONF_VALUE_STRING,
                                            &err);
      g_free(key);
      cb_data.network_types = network_types;

      if (err)
      {
        ILOG_WARN("could not find service provider network types: %s",
                  err->message);
        g_clear_error(&err);
      }

      filename = g_strconcat("/usr/lib/icd2", "/", name, NULL);

      if (name && service_type && *service_type && network_types)
      {
        if (icd_plugin_load(filename, name, "icd_srv_init",
                            icd_srv_provider_init, &cb_data))
        {
            rv = TRUE;
        }
      }

      while (network_types);
      {
        g_free(network_types->data);
        network_types = g_slist_delete_link(network_types, network_types);
      }

      g_free(name);
      g_free(filename);
    }

    g_free(dir);
    dirs = g_slist_delete_link(dirs, dirs);
  }

  if (!rv)
    ILOG_INFO("no service provider modules loaded");

  return rv;
}

static void
icd_srv_provider_free_list(gpointer key, gpointer value, gpointer user_data)
{
  g_slist_free((GSList *)value);
}

void
icd_srv_provider_unload_modules(struct icd_context *icd_ctx)
{
  GSList *l;

  ILOG_DEBUG("Unloading service provider modules");
  l = icd_ctx->srv_module_list;

  while (l)
  {
    struct icd_srv_module *module = (struct icd_srv_module *)l->data;
    GSList *next = l->next;

    if (module->pid_list)
    {
      ILOG_ERR("Module %s still has child processes running but unloading anyway",
               module->name);
    }

    if (module->srv.srv_destruct)
    {
      ILOG_DEBUG("Calling srv_destruct of module %s", module->name);
      module->srv.srv_destruct(&module->srv.private);
    }
    else
      ILOG_DEBUG("No srv_destruct function in module %s", module->name);

    icd_plugin_unload_module(module->handle);
    g_free(module->name);
    g_free(module);
    icd_ctx->srv_module_list = g_slist_remove_link(icd_ctx->srv_module_list, l);
    l = next;
  }

  if (icd_ctx->srv_type_to_srv_module)
    g_hash_table_destroy(icd_ctx->srv_type_to_srv_module);

  icd_ctx->srv_type_to_srv_module = NULL;

  if (icd_ctx->nw_type_to_srv_module)
  {
    g_hash_table_foreach(icd_ctx->nw_type_to_srv_module,
                         icd_srv_provider_free_list, NULL);
    g_hash_table_destroy(icd_ctx->nw_type_to_srv_module);
  }

  icd_ctx->nw_type_to_srv_module = NULL;
}
