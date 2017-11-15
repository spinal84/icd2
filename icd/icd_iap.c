#include "icd_context.h"
#include "icd_iap.h"
#include "icd_log.h"
#include "icd_request.h"

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
