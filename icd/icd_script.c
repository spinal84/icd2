#include <gconf/gconf-client.h>

#include <stdlib.h>

#include "icd_script.h"
#include "icd_log.h"

#define ICD_SCRIPT_MIN_TIMEOUT   1
#define ICD_SCRIPT_DEFAULT_TIMEOUT   15
#define ICD_SCRIPT_MAX_TIMEOUT   120
#define ICD_SCRIPT_GCONF_PATH   ICD_GCONF_SETTINGS "/network_scripts/timeout"
#define SCRIPT_IFACE   "IFACE"
#define SCRIPT_LOGICAL   "LOGICAL"
#define SCRIPT_ADDRFAM   "ADDRFAM"
#define SCRIPT_METHOD   "METHOD"
#define SCRIPT_MODE   "MODE"
#define SCRIPT_PHASE   "PHASE"
#define SCRIPT_VERBOSITY   "VERBOSITY"
#define SCRIPT_VERBOSITY_VALUE   "0"
#define SCRIPT_PATH   "PATH"
#define SCRIPT_PATH_VALUE
#define SCRIPT_IAP_ID   "ICD_CONNECTION_ID"
#define SCRIPT_IAP_TYPE   "ICD_CONNECTION_TYPE"
#define SCRIPT_PROXY_UNSET   "ICD_PROXY_UNSET"

static GSList *script_data = NULL;

#define SETENV(e, v) \
  setenv(e, v, 1); \
  ILOG_DEBUG(e"=%s", v);

struct icd_script_data {
  pid_t pid;
  guint timeout_id;
  icd_script_cb_fn cb;
  gpointer user_data;
};

static GSList **
icd_script_get()
{
  return &script_data;
}

static gint
icd_script_timeout_secs (void)
{
  gint timeout;
  GError *err = NULL;
  GConfClient *gconf = gconf_client_get_default();
  GConfValue *val;

  val = gconf_client_get(gconf,
                         "/system/osso/connectivity/network_scripts/timeout",
                         &err);

  g_object_unref(gconf);

  if (err || !G_VALUE_HOLDS_INT(val))
  {
    ILOG_INFO("script timeout value not set, using default %ds",
              ICD_SCRIPT_DEFAULT_TIMEOUT);

    if (err)
      g_error_free(err);

    timeout = ICD_SCRIPT_DEFAULT_TIMEOUT ;
  }
  else
  {
    timeout = gconf_value_get_int(val);
    gconf_value_free(val);

    if (timeout < ICD_SCRIPT_MIN_TIMEOUT || timeout > ICD_SCRIPT_MAX_TIMEOUT)
    {
      ILOG_WARN("script timeout %d not in range %d-%d, reset to %ds",
                timeout, ICD_SCRIPT_MIN_TIMEOUT, ICD_SCRIPT_MAX_TIMEOUT,
                ICD_SCRIPT_DEFAULT_TIMEOUT);
    }
  }

  return timeout * 1000;
}

static gboolean
icd_script_timeout(gpointer data)
{
  pid_t pid = *(pid_t *)data;

  g_free(data);
  ILOG_INFO("script exceeded time to live value, killed");

  kill(pid, 9);
  return FALSE;
}

static pid_t
icd_script_run (const gchar *script, const gchar *iface, const gchar *mode,
                const gchar *phase, const gchar *iap_id, const gchar *iap_type,
                gboolean remove_proxies, const struct icd_iap_env *env,
                icd_script_cb_fn cb, gpointer user_data)
{
  pid_t pid, *ppid;
  struct icd_script_data *script_data;
  GSList **scripts;
  gchar *path = g_strdup_printf("/etc/network/if-%s.d", mode);

  pid = fork();

  if (pid == -1)
  {
    ILOG_ERR("forking of %s script failed", mode);
    g_free(path);
    return pid;
  }

  if (!pid)
  {
    ILOG_DEBUG("running %s scripts in %s, setting following env:", mode, path);

    if (iface)
    {
      SETENV("IFACE", iface);
      SETENV("LOGICAL", iface);
    }

    if (remove_proxies)
      SETENV("ICD_PROXY_UNSET", "1");

    if (env && env->addrfam)
      SETENV("ADDRFAM", env->addrfam);

    if (script)
      SETENV("MODE", script);

    if (phase)
      SETENV("PHASE", phase);

    SETENV("VERBOSITY", "0");
    SETENV("PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    if (iap_id)
      SETENV("ICD_CONNECTION_ID", iap_id);

    if (iap_type)
      SETENV("ICD_CONNECTION_TYPE", iap_type);

    if (env)
    {
      GSList *l;

      for (l = env->envlist; l; l = l->next)
      {
        char *envs = (char *)l->data;

        if (envs)
        {
          ILOG_DEBUG("%s", envs);
          putenv(envs);
        }
      }
    }

    execl("/bin/run-parts", "/bin/run-parts", path, NULL);
    exit(1);
  }

  g_free(path);

  script_data = g_new0(struct icd_script_data, 1);
  script_data->pid = pid;
  script_data->cb = cb;
  script_data->user_data = user_data;

  scripts = icd_script_get();
  *scripts = g_slist_prepend(*scripts, script_data);

  ppid = g_new(pid_t, 1);
  *ppid = pid;
  script_data->timeout_id = g_timeout_add(1000 * icd_script_timeout_secs(),
                                          icd_script_timeout, ppid);

  return pid;
}
