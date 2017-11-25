#include <gconf/gconf.h>
#include "icd_policy_api.h"
#include "policy_api.h"
#include "icd_plugin.h"
#include "icd_log.h"
#include "icd_request.h"
#include "icd_iap.h"
#include "icd_scan.h"
#include "network_api.h"
#include "icd_type_modules.h"
#include "icd_network_priority.h"
#include "icd_srv_provider.h"

/** prefix for the ICd policy API modules */
#define ICD_POLICY_API_PREFIX   "libicd_policy_"

/** name of the policy API init function */
#define ICD_POLICY_INIT   "icd_policy_init"

struct icd_policy_api_async_data;
/**
 * @brief Function prototype for calling the actual asynchronous policy function
 *
 * @param module the policy module
 * @param request the requested connection
 * @param async_data data for the asynchronous function call
 *
 * @return TRUE if the module has a policy function that will cause the callback
 * to be called; FALSE if no policy function is called
 *
 */
typedef gboolean(* icd_policy_api_async_call_fn)(
    struct icd_policy_module *module, struct icd_policy_request *request,
    struct icd_policy_api_async_data *async_data);

/** asynchronous policy module function data */
struct icd_policy_api_async_data {
  /** callback to call with final policy decision */
  icd_policy_api_async_call_fn call_policy;

  /** policy result callback data */
  gpointer user_data;

  /** current policy module in list */
  GSList *module_list;
};

/**
 * @brief Policy module function that will be called once for each policy
 * module until #ICD_POLICY_REJECTED is returned
 *
 * @param module the policy module
 * @param request the request to apply policy to
 * @param user_data user data to pass to the module
 *
 * @return #ICD_POLICY_REJECTED if the policy got rejected,
 * #ICD_POLICY_ACCEPTED otherwise
 *
 */
typedef enum icd_policy_status(* icd_policy_api_run_module_fn)(
    struct icd_policy_module *module, struct icd_policy_request *request,
    gpointer user_data);

const gchar const* icd_policy_api_state[] = {
  "ICD_POLICY_ACCEPTED",
  "ICD_POLICY_MERGED",
  "ICD_POLICY_WAITING",
  "ICD_POLICY_REJECTED"
};

/**
 * @brief Module iterator for the 'cancel_request' function.
 *
 * @param module the policy module
 * @param request the request to cancel
 * @param user_data user data; not used
 *
 * @return #ICD_POLICY_ACCEPTED to iterate through all policy modules
 *
 */
static enum icd_policy_status
icd_policy_api_request_cancel_iter(struct icd_policy_module *module,
                                   struct icd_policy_request *request,
                                   gpointer user_data)
{
  if (module->policy.cancel_request)
  {
    ILOG_INFO("module '%s' cancel function called for request %p", module->name,
              request);

    module->policy.cancel_request(request, &module->policy.private);
  }

  return ICD_POLICY_ACCEPTED;
}

/**
 * @brief Iterate over all the modules and call the policy callback function for
 * each of them.
 *
 * @param policy_fn the policy callback function call for each module
 * @param request the request to apply policy to
 * @param user_data user data to pass to the function
 *
 * @return enum #icd_policy_status
 *
 */
static enum icd_policy_status
icd_policy_api_run(icd_policy_api_run_module_fn policy_fn,
                   struct icd_policy_request *request, gpointer user_data)
{
  struct icd_context *icd_ctx = icd_context_get();
  GSList *l;

  if (!icd_ctx || !policy_fn)
  {
    ILOG_ERR("icd_ctx or foreach_fn cannot be NULL");
    return ICD_POLICY_REJECTED;

  }

  for (l = icd_ctx->policy_module_list; l; l = l->next)
  {
    struct icd_policy_module *pm = (struct icd_policy_module *)l->data;

    if (pm)
    {
      if (policy_fn(pm, request, user_data) == ICD_POLICY_REJECTED)
        return ICD_POLICY_REJECTED;
    }
    else
      ILOG_WARN("module list has NULL module data");
  }

  return ICD_POLICY_ACCEPTED;
}

/**
 * @brief Cancel a request that is in ICD_POLICY_WAITING state by informing each
 * policy module.
 *
 * @param req the policy request structure
 *
 */
void
icd_policy_api_request_cancel(struct icd_policy_request *req)
{
  struct icd_request *request = (struct icd_request *)req->request_token;

  if (request->state == ICD_REQUEST_WAITING ||
      request->state == ICD_REQUEST_POLICY_PENDING)
  {
    icd_policy_api_run(icd_policy_api_request_cancel_iter, req, 0);
  }
  else
  {
    ILOG_ERR("Request %p is not in ICD_REQUEST_WAITING or ICD_REQUEST_POLICY_PENDING state",
             request);
  }
}

/**
 * @brief Go through all connections and add them to the list in reverse order
 *
 * @param iap current iap
 * @param user_data connection list
 *
 * @return TRUE to iterate over all connections
 *
 */
static gboolean
icd_policy_api_existing_conn_foreach(struct icd_iap *iap, gpointer user_data)
{
  GSList **l = (GSList **)user_data;

  *l = g_slist_prepend(*l, &iap->connection);

  return TRUE;
}

/**
 * @brief Get the list of existing connections
 *
 * @return list of connections; the caller needs to free only the GSList.
 *
 */
static GSList *
icd_policy_api_existing_conn_get(void)
{
  GSList *l = NULL;

  icd_iap_foreach(icd_policy_api_existing_conn_foreach, &l);

  return l;
}

/**
 * @brief  Iterator for the disconnect policy
 *
 * @param module the policy module
 * @param request the request to apply policy to
 * @param user_data reference count
 *
 * @return enum #icd_policy_status
 *
 */
static enum icd_policy_status
icd_policy_api_iap_disconnect_iter(struct icd_policy_module *module,
                                   struct icd_policy_request *request,
                                   gpointer user_data)
{
  enum icd_policy_status rv;
  GSList *l;

  if (!module->policy.disconnect)
    return ICD_POLICY_ACCEPTED;

  ILOG_INFO("running module '%s' disconnect policy", module->name);

  l = icd_policy_api_existing_conn_get();
  rv = module->policy.disconnect(request, GPOINTER_TO_INT(user_data), l,
                                 &module->policy.private);
  g_slist_free(l);

  return rv;
}

/**
 * @brief Disconnect policy called when ICd attempts to disconnect from a
 * network
 *
 * @param connection the connection that is to be tried
 * @param refcount a reference count on the number of applications using this
 * connection or -1 if disconnect forced by Connectivity UI
 *
 * @return enum #icd_policy_status
 *
 */
enum icd_policy_status
icd_policy_api_iap_disconnect(struct icd_policy_request *connection,
                              gint refcount)
{
  return icd_policy_api_run(icd_policy_api_iap_disconnect_iter, connection,
                            GINT_TO_POINTER(refcount));
}
