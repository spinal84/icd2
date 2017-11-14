#ifndef ICD_REQUEST_H
#define ICD_REQUEST_H

#include <dbus/dbus.h>
#include <glib.h>
#include "policy_api.h"
#include "icd_tracking_info.h"
#include "icd_iap.h"

enum icd_request_status {
  ICD_REQUEST_POLICY_PENDING = 0,
  ICD_REQUEST_WAITING,
  ICD_REQUEST_CHANGETO,
  ICD_REQUEST_MERGED,
  ICD_REQUEST_CONNECTING_IAPS,
  ICD_REQUEST_SUCCEEDED,
  ICD_REQUEST_DENIED,
  ICD_REQUEST_DISCONNECTED,

  ICD_REQUEST_MAX
};

typedef void (*icd_request_cb_fn) (enum icd_request_status status,
                                   gpointer user_data);

struct icd_request {
  enum icd_request_status state;
  GSList *users;
  gboolean multi_iaps;
  GSList *try_iaps;
  struct icd_policy_request req;
};

typedef gpointer (*icd_request_foreach_fn) (struct icd_request *request,
                                            gpointer user_data);

gpointer icd_request_foreach (icd_request_foreach_fn fn,
                              gpointer user_data);
void icd_request_free_iaps (struct icd_request *request);
struct icd_request *icd_request_find (const gchar *network_type,
                                      const guint network_attrs,
                                      const gchar *network_id);
struct icd_request *icd_request_find_by_iap (const gchar *network_type,
                                             const guint network_attrs,
                                             const gchar *network_id);
struct icd_request *icd_request_find_by_iap_id (const gchar *iap_id,
                                                const gboolean is_local);
void icd_request_send_ack (struct icd_request *request,
                           struct icd_iap *iap);
void icd_request_send_nack (struct icd_request *request);
void icd_request_add_iap (struct icd_request *request,
                          gchar *service_type,
                          guint service_attrs,
                          gchar *service_id,
                          gchar *network_type,
                          guint network_attrs,
                          gchar *network_id,
                          gint network_priority);
struct icd_request *icd_request_new (guint policy_attrs,
                                     const gchar *service_type,
                                     const guint service_attrs,
                                     const gchar *service_id,
                                     const gchar *network_type,
                                     const guint network_attrs,
                                     const gchar *network_id);
void icd_request_make (struct icd_request *request);
gboolean icd_request_merge (struct icd_request *merge_request,
                            struct icd_request *existing);
void icd_request_cancel (struct icd_request *request, guint policy_attrs);
void icd_request_tracking_info_remove (struct icd_request *request,
                                       struct icd_tracking_info *track);
gboolean icd_request_tracking_info_delete (const gchar *sender);
void icd_request_tracking_info_add (struct icd_request *request,
                                    struct icd_tracking_info *track);


#endif
