#include <string.h>
#include <osso-ic.h>
#include <osso-ic-dbus.h>
#include "icd_request.h"
#include "icd_context.h"
#include "icd_iap.h"
#include "icd_log.h"
#include "policy_api.h"
#include "icd_policy_api.h"
#include "network_api.h"
#include "icd_osso_ic.h"
#include "icd_status.h"
#include "icd_gconf.h"
#include "icd_dbus_api.h"
#include "icd_name_owner.h"
#include "icd_network_priority.h"

/** ICd request status names */
static const gchar *icd_request_status_names[ICD_REQUEST_MAX] = {
  "ICD_REQUEST_POLICY_PENDING",
  "ICD_REQUEST_WAITING",
  "ICD_REQUEST_CHANGETO",
  "ICD_REQUEST_MERGED",
  "ICD_REQUEST_CONNECTING_IAPS",
  "ICD_REQUEST_SUCCEEDED",
  "ICD_REQUEST_DENIED",
  "ICD_REQUEST_DISCONNECTED"
};

/**
 * @brief Helper function for comparing two strings where a NULL string is equal
 * to another NULL string
 *
 * @param a string A
 * @param b string B
 *
 * @return TRUE if equal, FALSE if unequal
 *
 */
inline static gboolean
icd_request_string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

/**
 * @brief Foreach function for network finding
 *
 * @param request the request
 * @param user_data the network to search for
 *
 * @return the request that has a matching network connection or NULL if none
 *
*/
static gpointer
icd_request_find_foreach(struct icd_request *request, gpointer user_data)
{
  struct icd_policy_request *preq = (struct icd_policy_request *)user_data;
  guint pattrs = preq->network_attrs;
  guint attrs = request->req.network_attrs;

  if (((pattrs & ICD_NW_ATTR_IAPNAME) == (attrs & ICD_NW_ATTR_IAPNAME)) &&
      ((attrs & ICD_NW_ATTR_LOCALMASK) == (pattrs & ICD_NW_ATTR_LOCALMASK)) &&
      icd_request_string_equal(request->req.network_type, preq->network_type) &&
      icd_request_string_equal(request->req.network_id, preq->network_id) )
  {

    ILOG_DEBUG("found request %p with %s/%0x/%s", request, preq->network_type,
               preq->network_attrs, preq->network_id);

    return request;
  }

  return NULL;
}

/**
 * @brief Iterate over all requests and call the user given function for each
 * of them
 *
 * @param fn the function
 * @param user_data user data to pass to the function
 *
 * @return the pointer returned from the user function
 *
 */
gpointer
icd_request_foreach(icd_request_foreach_fn fn, gpointer user_data)
{
  struct icd_context *icd_ctx = icd_context_get();
  GSList *l;

  if (!fn)
  {
    ILOG_ERR("no foreach request function");
    return NULL;
  }

  for (l = icd_ctx->request_list; l; l = l->next)
  {
    if (l->data)
    {
      gpointer rv = fn((struct icd_request *)l->data, user_data);

      if (rv)
        return rv;
    }
    else
      ILOG_ERR("NULL request in foreach function");
  }

  return NULL;
}

/**
 * @brief Find a request
 *
 * @param network_type requested network type
 * @param network_attrs requested network attributes
 * @param network_id requested (meta) IAP name
 *
 * @return the first (and only) request found or NULL
 *
 */
struct icd_request *
icd_request_find(const gchar *network_type, const guint network_attrs,
                 const gchar *network_id)
{
  struct icd_policy_request user_data;

  if (!network_id)
    return NULL;

  user_data.network_type = (gchar *)network_type;
  user_data.network_attrs = network_attrs;
  user_data.network_id = (gchar *)network_id;

  return (struct icd_request *)icd_request_foreach(icd_request_find_foreach,
                                                   &user_data);
}

/**
 * @brief Iterator function for removal by D-Bus sender id
 *
 * @param request the request
 * @param user_data user data passed to #icd_request_tracking_info_delete().
 *
 * @return the request in which the sender id was found or NULL
 *
 */
static gpointer
icd_request_tracking_info_delete_foreach(struct icd_request *request,
                                         gpointer user_data)
{
  GSList *l;
  const char *sender = (const char *)user_data;

  for (l = request->users; l; l = l->next)
  {
    struct icd_tracking_info *track = (struct icd_tracking_info *)l->data;

    if (track)
    {
      if (track->sender && !strcmp(track->sender, sender))
      {
        icd_name_owner_remove_filter(sender);
        request->users = g_slist_remove_link(request->users, l);
        g_slist_free_1(l);
        icd_tracking_info_free(track);
        return request;
      }
    }
    else
      ILOG_ERR("tracking info NULL in request %p", request);
  }

  return NULL;
}

/**
 * @brief Delete a tracked user by D-Bus id
 *
 * @param sender the D-Bus sender
 *
 * @return TRUE if the sender was deleted; FALSE on error or sender not found
 *
 */
gboolean
icd_request_tracking_info_delete(const gchar *sender)
{
  if (!sender)
  {
    ILOG_ERR("sender NULL when deleting from request");

    return FALSE;
  }

  return icd_request_foreach(
        icd_request_tracking_info_delete_foreach, (gpointer)sender) != NULL;
}

void
icd_request_send_nack(struct icd_request *request)
{
  icd_osso_ic_send_nack(request->users);
  icd_dbus_api_send_nack(request->users, NULL);
  g_slist_free(request->users);
  request->users = NULL;
}

static void
icd_request_free(struct icd_request *request)
{
  struct icd_context *icd_ctx = icd_context_get();

  icd_ctx->request_list = g_slist_remove(icd_ctx->request_list, request);

  if (request->try_iaps)
    ILOG_CRIT("Request %p still has IAPs when free called", request);

  if (request->users)
  {
    ILOG_CRIT("Request %p still has dbus user tracking info when free called",
              request);
  }

  g_free(request->req.service_type);
  g_free(request->req.service_id);
  g_free(request->req.network_type);
  g_free(request->req.network_id);
  g_free(request);
}

static void
icd_request_update_status(enum icd_request_status status,
                          struct icd_request *request)
{
  ILOG_DEBUG("request %p with status %s", request,
             icd_request_status_names[status]);

  request->state = status;
}

void
icd_request_free_iaps(struct icd_request *request)
{
  GSList *l;

  for (l = request->try_iaps; l; request->try_iaps = l)
  {
    struct icd_iap *iap = (struct icd_iap *)l->data;

    if (!iap)
      ILOG_CRIT("IAP in request list is NULL");
    else
      icd_iap_free(iap);

    l = g_slist_delete_link(l, l);
  }
}

void
icd_request_cancel(struct icd_request *request, guint policy_attrs)
{
  struct icd_context *icd_ctx = icd_context_get();

  if (request->try_iaps)
  {
    if (request->state && request->state != ICD_REQUEST_WAITING)
    {
      gint refcount;
      struct icd_iap *iap = (struct icd_iap *)request->try_iaps->data;

      if (policy_attrs & ICD_POLICY_ATTRIBUTE_CONN_UI)
        refcount = -1;
      else
        refcount = g_slist_length(request->users);

      if (!icd_ctx->shutting_down &&
          icd_policy_api_iap_disconnect(&iap->connection, refcount))
      {
        ILOG_INFO("disconnect policy refused to disconnect iap %p", iap);
      }
      else
      {
        icd_status_disconnect(iap, NULL, NULL);
        request->try_iaps = g_slist_remove(request->try_iaps, iap);
        icd_request_free_iaps(request);
        request->try_iaps = g_slist_prepend(request->try_iaps, iap);
        icd_iap_disconnect(iap, NULL);
      }

      return;
    }

    goto cancel_policy_req;
  }

  if (request->state == ICD_REQUEST_POLICY_PENDING ||
      request->state == ICD_REQUEST_WAITING)
  {
cancel_policy_req:
    ILOG_DEBUG("canceling policy request %p, state %d", &request->req,
               request->state);

    icd_policy_api_request_cancel(&request->req);
  }

  icd_request_free_iaps(request);
  icd_request_update_status(ICD_REQUEST_DENIED, request);

  ILOG_INFO("request %p cancelled", request);

  icd_request_free(request);
}