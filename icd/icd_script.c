#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <gconf/gconf-client.h>
#include <osso-ic-gconf.h>
#include "icd_log.h"
#include "icd_script.h"

/** min time in seconds that a script can be run */
#define ICD_SCRIPT_MIN_TIMEOUT   1
/** default time in seconds that a script can be run */
#define ICD_SCRIPT_DEFAULT_TIMEOUT   15
/** max time in seconds that a script can be run */
#define ICD_SCRIPT_MAX_TIMEOUT   120
/** gconf location for timeout value */
#define ICD_SCRIPT_GCONF_PATH   ICD_GCONF_SETTINGS "/network_scripts/timeout"
/** physical name of the interface being processed */
#define SCRIPT_IFACE   "IFACE"
/** logical name of the interface being processed */
#define SCRIPT_LOGICAL   "LOGICAL"
/** address family of the interface */
#define SCRIPT_ADDRFAM   "ADDRFAM"
/** method of the interface */
#define SCRIPT_METHOD   "METHOD"
/** 'start' if going up, 'stop' if going down */
#define SCRIPT_MODE   "MODE"
/** as per MODE, but with finer granularity, distinguishing the pre-up,
 * post-up, pre-down and post-down phases */
#define SCRIPT_PHASE   "PHASE"
/** verbosity */
#define SCRIPT_VERBOSITY   "VERBOSITY"
/** script verbosity value */
#define SCRIPT_VERBOSITY_VALUE   "0"
/** the command search path */
#define SCRIPT_PATH   "PATH"
/** script search path value */
#define SCRIPT_PATH_VALUE
/** ICd IAP identifier; for now escaped gconf name */
#define SCRIPT_IAP_ID   "ICD_CONNECTION_ID"
/** ICd IAP type */
#define SCRIPT_IAP_TYPE   "ICD_CONNECTION_TYPE"
/** Unset proxies */
#define SCRIPT_PROXY_UNSET   "ICD_PROXY_UNSET"

static const gchar const* reserved_env_vars[] = {
  SCRIPT_ADDRFAM,
  SCRIPT_IFACE,
  SCRIPT_LOGICAL,

  SCRIPT_MODE,
  SCRIPT_PHASE,

  SCRIPT_PATH,
  SCRIPT_IAP_ID,
  SCRIPT_IAP_TYPE,
  NULL
};

static GSList *script_data = NULL;

#define SETENV(e, v) \
do {\
  setenv(e, v, 1); \
  ILOG_DEBUG(e"=%s", v); \
} while (0)

/** structure to keep track of running scripts */
struct icd_script_data {
  /** pid */
  pid_t pid;
  /** timeout id */
  guint timeout_id;
  /** callback */
  icd_script_cb_fn cb;
  /** callback user data */
  gpointer user_data;
};

/**
 * Get the list of running scripts
 * @return the list
 */
static GSList **
icd_script_get()
{
  return &script_data;
}

/**
 * Read the script timeout value from gconf
 * @return script timeout value between #ICD_SCRIPT_MIN_TIMEOUT and
 *         #ICD_SCRIPT_MAX_TIMEOUT.
 */
static gint
icd_script_timeout_secs (void)
{
  gint timeout;
  GError *err = NULL;
  GConfClient *gconf = gconf_client_get_default();
  GConfValue *val = gconf_client_get(gconf, ICD_SCRIPT_GCONF_PATH, &err);

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

/**
 * Script timeout function
 * @param  data  pointer to pid of the script that timed out
 * @return FALSE in order not to run again
 */
static gboolean
icd_script_timeout(gpointer data)
{
  pid_t pid = *(pid_t *)data;

  g_free(data);
  ILOG_INFO("script exceeded time to live value, killed");

  kill(pid, SIGKILL);
  return FALSE;
}

/**
 * Forks and execs the network script
 *
 * @param  script          the script, i.e. 'pre-up', 'post-up', 'pre-down',
 *                         'post-down'
 * @param  iface           interface name
 * @param  method          address configuration method, i.e. 'static',
 *                         'manual', 'dhcp', 'ppp', etc.
 * @param  mode            either 'start' or 'stop'
 * @param  phase           script phase, i.e. 'pre-up', 'post-up',
 *                         'pre-down', 'post-down'
 * @param  iap_id          Unique IAP identifier, currently the escaped iap
 *                         name
 * @param  iap_type        IAP type
 * @param  remove_proxies  TRUE to set ICD_PROXY_UNSET=1
 *
 * @return pid of child process or -1 on error
 */
static pid_t
icd_script_exec (const gchar * script, const gchar *iface, const gchar *mode,
                 const gchar *phase, const gchar *iap_id, const gchar *iap_type,
                 const gboolean remove_proxies, const struct icd_iap_env *env)
{
  gchar *path = g_strdup_printf("/etc/network/if-%s.d", mode);
  pid_t pid = fork();

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
      SETENV(SCRIPT_IFACE, iface);
      SETENV(SCRIPT_LOGICAL, iface);
    }

    if (remove_proxies)
      SETENV(SCRIPT_PROXY_UNSET, "1");

    if (env && env->addrfam)
      SETENV(SCRIPT_ADDRFAM, env->addrfam);

    if (script)
      SETENV(SCRIPT_MODE, script);

    if (phase)
      SETENV(SCRIPT_PHASE, phase);

    SETENV(SCRIPT_VERBOSITY, SCRIPT_VERBOSITY_VALUE);
    SETENV(SCRIPT_PATH,
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    if (iap_id)
      SETENV(SCRIPT_IAP_ID, iap_id);

    if (iap_type)
      SETENV(SCRIPT_IAP_TYPE, iap_type);

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

  return pid;
}

/**
 * Run network script and start waiting for the result
 *
 * @param  script          the script
 * @param  iface           interface name
 * @param  mode            mode
 * @param  phase           script phase, i.e. 'pre-up', 'post-up',
 *                         'pre-down', 'post-down'
 * @param  cb              callback function
 * @param  user_data       user data for callback function
 * @param  iap_id          Unique IAP identifier, currently the escaped iap
 *                         name
 * @param  iap_type        IAP type
 * @param  remove_proxies  whether to remove http, etc. proxies
 * @param  env             rest of the environment variables
 *
 * @return pid of child process or -1 on error
 */
static pid_t
icd_script_run (const gchar *script, const gchar *iface, const gchar *mode,
                const gchar *phase, const gchar *iap_id, const gchar *iap_type,
                gboolean remove_proxies, const struct icd_iap_env *env,
                icd_script_cb_fn cb, gpointer user_data)
{
  pid_t pid;
  GSList **scripts;

  pid = icd_script_exec(script, iface, mode, phase,iap_id, iap_type,
                        remove_proxies,env);

  if (pid != -1)
  {
    struct icd_script_data *script_data = g_new0(struct icd_script_data, 1);
    pid_t *ppid;

    script_data->pid = pid;
    script_data->cb = cb;
    script_data->user_data = user_data;

    scripts = icd_script_get();
    *scripts = g_slist_prepend(*scripts, script_data);

    ppid = g_new(pid_t, 1);
    *ppid = pid;
    script_data->timeout_id = g_timeout_add(1000 * icd_script_timeout_secs(),
                                            icd_script_timeout, ppid);
  }

  return pid;
}

/**
 * Run pre-up scripts
 *
 * @param  iap_id     Unique IAP identifier, currently the escaped iap name
 * @param  iap_type   IAP type
 * @param  env        script environment variables
 * @param  cb         callback
 * @param  user_data  user data for the callback
 *
 * @return the process id of the running script, -1 on error whereby the
 *         callback will not be called
 */
pid_t
icd_script_pre_up(const gchar *iap_id, const gchar *iap_type,
                  const struct icd_iap_env *env, icd_script_cb_fn cb,
                  gpointer user_data)
{
  return icd_script_run("start", NULL, "pre-up", "pre-up", iap_id, iap_type,
                        FALSE, env, cb, user_data);
}

/**
 * Run post-up scripts
 *
 * @param  iface      interface name
 * @param  iap_id     Unique IAP identifier, currently the escaped iap name
 * @param  iap_type   IAP type
 * @param  env        script environment variables
 * @param  cb         callback
 * @param  user_data  user data for the callback
 *
 * @return the process id of the running script, -1 on error whereby the
 *         callback will not be called
 */
pid_t
icd_script_post_up(const gchar *iface, const gchar *iap_id,
                   const gchar *iap_type, const struct icd_iap_env *env,
                   icd_script_cb_fn cb, gpointer user_data)
{
  return icd_script_run("start", iface, "up", "post-up", iap_id, iap_type,
                        FALSE, env, cb, user_data);
}

/**
 * Run pre-down scripts
 *
 * @param  iface           interface name
 * @param  iap_id          Unique IAP identifier, currently the escaped iap
 *                         name
 * @param  iap_type        IAP type
 * @param  remove_proxies  remove http, etc. proxies if TRUE
 * @param  env             script environment variables
 * @param  cb              callback
 * @param  user_data       user data for the callback
 *
 * @return the process id of the running script, -1 on error whereby the
 *         callback will not be called
 */
pid_t
icd_script_pre_down(const gchar *iface, const gchar *iap_id,
                    const gchar *iap_type, gboolean remove_proxies,
                    const struct icd_iap_env *env, icd_script_cb_fn cb,
                    gpointer user_data)
{
  return icd_script_run("stop", iface, "down", "pre-down", iap_id, iap_type,
                        remove_proxies, env, cb, user_data);
}

/**
 * Run post-down scripts
 *
 * @param  iface      interface name
 * @param  iap_id     Unique IAP identifier, currently the escaped iap name
 * @param  iap_type   IAP type
 * @param  env        script environment variables
 * @param  cb         callback
 * @param  user_data  user data for the callback
 *
 * @return the process id of the running script, -1 on error whereby the
 *         callback will not be called
 */
pid_t
icd_script_post_down(const gchar *iface, const gchar *iap_id,
                     const gchar *iap_type, const struct icd_iap_env *env,
                     icd_script_cb_fn cb, gpointer user_data)
{
  return icd_script_run("stop", iface, "post-down", "post-down", iap_id,
                        iap_type, FALSE, env, cb, user_data);
}

/**
 * Cancel a running script
 * @param pid  script process id
 */
void
icd_script_cancel(const pid_t pid)
{
  GSList **scripts = icd_script_get();
  GSList *script = *scripts;

  while (script)
  {
    GSList *next = script->next;
    struct icd_script_data *script_data =
        (struct icd_script_data *)script->data;

    if (script->data && script_data->pid == pid)
    {
      ILOG_INFO("script pid %d timeout id %d cancelled", script_data->pid,
                script_data->timeout_id);

      g_source_remove(script_data->timeout_id);
      kill(script_data->pid, SIGKILL);
      g_free(script_data);
      *scripts = g_slist_delete_link(*scripts, script);
    }

    script = next;
  }
}

/**
 * Notification of an exited script process
 *
 * @param  pid         the process id
 * @param  exit_value  exit value
 *
 * @return TRUE if the pid was for a script, FALSE if the pid is unknown
 */
gboolean
icd_script_notify_pid(const pid_t pid, const gint exit_value)
{
  GSList **scripts = icd_script_get();
  GSList *l;

  for (l = *scripts; l; l = l->next)
  {
    struct icd_script_data *data = (struct icd_script_data *)l->data;

    if (data)
    {
      if (data->pid == pid)
      {
        ILOG_DEBUG("script cb %p with pid %d, exit value %d, user data %p",
                   data->cb, pid, exit_value, data->user_data);

        if (data->timeout_id)
        {
          g_source_remove(data->timeout_id);
          data->timeout_id = 0;
        }

        if (data->cb)
          data->cb(pid, exit_value, data->user_data);

        g_free(l->data);
        *scripts = g_slist_delete_link(*scripts, l);
        return TRUE;
      }
    }
    else
      ILOG_ERR("script list contains NULL data");
  }

  ILOG_INFO("script with pid %d does not exist", pid);

  return FALSE;
}

static const char *
icd_script_add_reserved_env_vars(gchar **env_vars, GSList **script_vars)
{
  const char *addrfam = NULL;

  while (*env_vars)
  {
    const char **resrvd = reserved_env_vars;
    gboolean add_it = TRUE;

    while (*resrvd)
    {
      size_t len = strlen(*resrvd);
      const gchar *env_var = *env_vars;
      const gchar *p;

      if (!strncmp(env_var, *resrvd, len))
      {
        p = &env_var[len];

        if (!*p || *p == '=')
        {
          add_it = FALSE;

          if (resrvd != reserved_env_vars)
          {
            ILOG_DEBUG("script not setting reserved env var '%s' ('%c')",
                       *resrvd, *p);
          }
          else
          {
            addrfam = p + 1;

            ILOG_DEBUG("script identifying with ADDRFAM env var value '%s'",
                       addrfam);
          }
        }
      }

      resrvd++;
    }

    if (add_it)
    {
      ILOG_DEBUG("script adding env var '%s'", *env_vars);
      *script_vars = g_slist_prepend(*script_vars, g_strdup(*env_vars));
    }

    env_vars++;
  }

  return addrfam;
}

void
icd_script_add_env_vars(struct icd_iap *iap, gchar **env_vars)
{

  GSList *l;
  gboolean updated = FALSE;
  struct icd_iap_env *env;
  GSList *script_vars = NULL;
  const gchar *addrfam =
      icd_script_add_reserved_env_vars(env_vars, &script_vars);

  for (l = iap->script_env; l; l = l->next)
  {
    GSList *env_data = (GSList *)l->data;

    if (env_data)
    {
      if (!env_data->data || (addrfam && !strcmp(addrfam, env_data->data)))
      {
        env_data->next = g_slist_concat(env_data->next, script_vars);

        ILOG_DEBUG("address family '%s' updated with env vars",
                   (char *)env_data->data);

        updated = TRUE;
      }
    }
    else
      ILOG_WARN("script env NULL");
  }

  if (updated)
    return;

  env = g_new0(struct icd_iap_env, 1);
  env->addrfam = g_strdup(addrfam);
  env->envlist = script_vars;
  ILOG_DEBUG("address family '%s' added to env", env->addrfam);
  iap->script_env = g_slist_prepend(iap->script_env, env);
}
