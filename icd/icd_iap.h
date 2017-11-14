#ifndef ICD_IAP_H
#define ICD_IAP_H

#include "policy_api.h"

enum icd_iap_state {
  ICD_IAP_STATE_DISCONNECTED = 0,
  ICD_IAP_STATE_SCRIPT_PRE_UP,
  ICD_IAP_STATE_LINK_UP,
  ICD_IAP_STATE_LINK_POST_UP,
  ICD_IAP_STATE_IP_UP,
  ICD_IAP_STATE_SRV_UP,
  ICD_IAP_STATE_SCRIPT_POST_UP,
  ICD_IAP_STATE_SAVING,
  ICD_IAP_STATE_CONNECTED,
  ICD_IAP_STATE_CONNECTED_DOWN,
  ICD_IAP_STATE_SRV_DOWN,
  ICD_IAP_STATE_IP_DOWN,
  ICD_IAP_STATE_IP_RESTART_SCRIPTS,
  ICD_IAP_STATE_LINK_PRE_DOWN,
  ICD_IAP_STATE_LINK_PRE_RESTART_SCRIPTS,
  ICD_IAP_STATE_LINK_DOWN,
  ICD_IAP_STATE_LINK_RESTART_SCRIPTS,
  ICD_IAP_STATE_SCRIPT_POST_DOWN,

  ICD_IAP_MAX_STATES
};

enum icd_iap_status {
  ICD_IAP_CREATED = 0,
  ICD_IAP_DISCONNECTED,
  ICD_IAP_BUSY,
  ICD_IAP_FAILED
};

struct icd_iap;

typedef void (*icd_iap_request_cb_fn) (enum icd_iap_status status,
                                       struct icd_iap *iap,
                                       gpointer user_data);

struct icd_iap_disconnect_data {
  gpointer function;
  gpointer *private;
};

struct icd_iap_env {
  gchar *addrfam;
  GSList *envlist;
};

struct icd_iap {
  gchar *id;
  gboolean id_is_local;

  enum icd_iap_state state;
  gboolean limited_conn;

  gchar *service_name;
  gchar *network_name;
  struct icd_policy_request connection;
  gchar *interface_name;
  guint idletimer_id;

  struct icd_network_module *busy;

  GSList *network_modules;
  GSList *current_module;
  GSList *ip_down_list;
  GSList *link_pre_down_list;
  GSList *link_down_list;

  gpointer srv_connect_cb;
  gpointer srv_connect_cb_user_data;
  gpointer srv_disconnect_cb;
  gpointer srv_disconnect_cb_user_data;

  enum icd_nw_layer restart_layer;
  enum icd_iap_state restart_state;
  guint restart_count;
  enum icd_nw_layer renew_layer;
  GSList *current_renew_module;

  gboolean user_interaction_done;
  gchar *err_str;

  gpointer save_dlg;
  icd_iap_request_cb_fn request_cb;
  gpointer request_cb_user_data;

  GSList *script_env;
  GSList *script_pids;
};

typedef gboolean (*icd_iap_foreach_fn) (struct icd_iap *iap,
                                        gpointer user_data);


void icd_iap_free (struct icd_iap *iap);
struct icd_iap *icd_iap_new (void);
gboolean icd_iap_id_create (struct icd_iap *iap, const gchar *new_name);
void icd_iap_connect (struct icd_iap* iap,
                      icd_iap_request_cb_fn request_cb,
                      gpointer user_data);
void icd_iap_disconnect (struct icd_iap *iap, const gchar *err_str);

void icd_iap_renew (struct icd_iap *iap, enum icd_nw_layer renew_layer);

void icd_iap_restart (struct icd_iap *iap, enum icd_nw_layer restart_layer);
guint icd_iap_get_ipinfo (struct icd_iap *iap,
                          icd_nw_ip_addr_info_cb_fn cb,
                          gpointer user_data);
gboolean icd_iap_get_ip_stats (struct icd_iap *iap,
                               icd_nw_ip_stats_cb_fn cb,
                               gpointer user_data);
gboolean icd_iap_get_link_post_stats (struct icd_iap *iap,
                                      icd_nw_link_post_stats_cb_fn cb,
                                      gpointer user_data);
gboolean icd_iap_get_link_stats (struct icd_iap *iap,
                                 icd_nw_link_stats_cb_fn cb,
                                 gpointer user_data);
struct icd_iap* icd_iap_find (const gchar *network_type,
                              const guint network_attrs,
                              const gchar *network_id);
struct icd_iap* icd_iap_find_by_id (const gchar *iap_id,
                                    const gboolean is_local);
struct icd_iap *icd_iap_foreach (icd_iap_foreach_fn fn, gpointer user_data);
gboolean icd_iap_rename (struct icd_iap *iap, const gchar *name);

#endif
