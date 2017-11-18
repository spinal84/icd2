#include "icd_context.h"
#include "icd_iap.h"
#include "icd_log.h"
#include "icd_request.h"

/** names for the different states */
const gchar* icd_iap_state_names[ICD_IAP_MAX_STATES] = {
  "ICD_IAP_STATE_DISCONNECTED",
  "ICD_IAP_STATE_SCRIPT_PRE_UP",
  "ICD_IAP_STATE_LINK_UP",
  "ICD_IAP_STATE_LINK_POST_UP",
  "ICD_IAP_STATE_IP_UP",
  "ICD_IAP_STATE_SRV_UP",
  "ICD_IAP_STATE_SCRIPT_POST_UP",
  "ICD_IAP_STATE_SAVING",
  "ICD_IAP_STATE_CONNECTED",
  "ICD_IAP_STATE_CONNECTED_DOWN",
  "ICD_IAP_STATE_SRV_DOWN",
  "ICD_IAP_STATE_IP_DOWN",
  "ICD_IAP_STATE_IP_RESTART_SCRIPTS",
  "ICD_IAP_STATE_LINK_PRE_DOWN",
  "ICD_IAP_STATE_LINK_PRE_RESTART_SCRIPTS",
  "ICD_IAP_STATE_LINK_DOWN",
  "ICD_IAP_STATE_LINK_RESTART_SCRIPTS",
  "ICD_IAP_STATE_SCRIPT_POST_DOWN"
};

/** names for status codes */
static const gchar* icd_iap_status_names[] =
 {
  "ICD_IAP_CREATED",
  "ICD_IAP_DISCONNECTED",
  "ICD_IAP_BUSY",
  "ICD_IAP_FAILED"
};

/**
 * @brief Iterate over all active IAPs
 *
 * @param fn function to call for each IAP
 * @param user_data user data to pass to the iterator function
 *
 * @return the IAP struct where fn returns FALSE, NULL otherwise or on error
 *
 */
struct icd_iap *
icd_iap_foreach(icd_iap_foreach_fn fn, gpointer user_data)
{
  struct icd_context *icd_ctx;
  GSList *l;

  if (!fn)
  {
    ILOG_ERR("iap iterator function NULL");
    return NULL;
  }

  icd_ctx = icd_context_get();
  l = icd_ctx->request_list;

  if (!l)
    return NULL;

  for (l = icd_ctx->request_list; l; l = l->next)
  {
    GSList *iaps;
    struct icd_request *request = (struct icd_request *)l->data;

    if (!request)
    {
      ILOG_ERR("request in list is NULL");
      continue;
    }

    iaps = request->try_iaps;

    if (!iaps)
    {
      ILOG_DEBUG("request %p has no IAPs", request);
      continue;
    }

    if (iaps->data)
    {
      struct icd_iap *iap = (struct icd_iap *)iaps->data;

      if (!fn(iap, user_data))
        return iap;
    }
    else
      ILOG_ERR("request %p has NULL iap in list", request);
  }

  return NULL;
}
