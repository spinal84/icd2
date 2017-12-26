#include <osso-ic-dbus.h>
#include <osso-ic-ui-dbus.h>
#include <osso-ic.h>

#include <string.h>

#include "icd_dbus.h"
#include "policy_api.h"
#include "icd_log.h"

struct policy_ask_data {
  gpointer *private;
  DBusPendingCall *pending;
  struct icd_policy_request *new_request;
  icd_policy_request_new_cb_fn policy_done_cb;
  gpointer policy_token;
};

static gboolean
string_equal(const char *a, const char *b)
{
  if (!a)
    return !b;

  if (b)
    return !strcmp(a, b);

  return FALSE;
}

static void
flight_mode_exit_cb(DBusPendingCall *pending, void *user_data)
{
  struct policy_ask_data *data = (struct policy_ask_data *)user_data;
  DBusMessage *reply = dbus_pending_call_steal_reply(pending);
  enum icd_policy_status policy_status;

  dbus_pending_call_unref(data->pending);
  data->pending = NULL;

  if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
    policy_status = ICD_POLICY_REJECTED;
  else
    policy_status = ICD_POLICY_WAITING;

  dbus_message_unref(reply);

  ILOG_DEBUG("policy iap ask exit flight mode dialog responded (%d)",
             policy_status);

  data->policy_done_cb(policy_status, data->new_request, data->policy_token);
  *(data->private) = g_slist_remove((GSList *)*(data->private), data);
  g_free(data);
}

static void
show_conn_dlg_cb(DBusPendingCall *pending, void *user_data)
{
  struct policy_ask_data *data = (struct policy_ask_data *)user_data;;
  DBusMessage *reply;
  enum icd_policy_status type;
  DBusMessage *message;
  const char *error_flight_mode;
  const char *ask;
  enum icd_policy_status policy_status = ICD_POLICY_REJECTED;
  reply = dbus_pending_call_steal_reply(pending);

  ILOG_DEBUG("policy iap ask pending returned");

  dbus_pending_call_unref(data->pending);
  data->pending = NULL;
  type = dbus_message_get_type(reply);

  if (type == DBUS_MESSAGE_TYPE_ERROR)
  {
    if (dbus_message_is_error(reply, ICD_UI_DBUS_ERROR_FLIGHT_MODE))
    {
      ILOG_DEBUG("policy iap ask flight mode error returned");
      ask = OSSO_IAP_ASK;
      error_flight_mode = ICD_DBUS_ERROR_FLIGHT_MODE;
      message = dbus_message_new_method_call(ICD_UI_DBUS_SERVICE,
                                             ICD_UI_DBUS_PATH,
                                             ICD_UI_DBUS_INTERFACE,
                                             ICD_UI_SHOW_RETRY_REQ);
      if (message)
      {
        if (dbus_message_append_args(message,
                                     DBUS_TYPE_STRING, &ask,
                                     DBUS_TYPE_STRING, &error_flight_mode,
                                     DBUS_TYPE_INVALID))
        {
          ILOG_DEBUG("policy iap asking to exit flight mode");
          data->pending = icd_dbus_send_system_mcall(message, 10000,
                                                     flight_mode_exit_cb, data);
          dbus_message_unref(message);

          if (data->pending)
          {
            dbus_message_unref(reply);
            return;
          }
        }
        else
        {
          ILOG_ERR("policy iap ask could not append args to exit flightmode request");
          dbus_message_unref(message);
        }
      }
      else
        ILOG_ERR("policy iap ask could not create exit flightmode request");

      data->policy_done_cb(ICD_POLICY_REJECTED, data->new_request,
                           data->policy_token);
      *(data->private) = g_slist_remove((GSList *)*(data->private), data);
      g_free(data);
      dbus_message_unref(reply);
      return;
    }
  }
  else
    policy_status = ICD_POLICY_WAITING;

  dbus_message_unref(reply);
  ILOG_DEBUG("'Select connection' dialog responded (%d)", policy_status);

  data->policy_done_cb(policy_status, data->new_request, data->policy_token);
  *(data->private) = g_slist_remove((GSList *)*(data->private), data);
  g_free(data);
}

static void
icd_policy_ask_request_new(struct icd_policy_request *new_request,
                           const GSList *existing_requests,
                           icd_policy_request_new_cb_fn policy_done_cb,
                           gpointer policy_token, gpointer *private)
{
  if (!strcmp(OSSO_IAP_ASK, new_request->network_id))
  {
    struct policy_ask_data *data;
    DBusMessage *message;
    dbus_bool_t failed = FALSE;

    if (new_request->attrs & ICD_POLICY_ATTRIBUTE_NO_INTERACTION)
      goto reject;

    message = dbus_message_new_method_call(ICD_UI_DBUS_SERVICE,
                                           ICD_UI_DBUS_PATH,
                                           ICD_UI_DBUS_INTERFACE,
                                           ICD_UI_SHOW_CONNDLG_REQ);
    if (!message)
    {
      ILOG_CRIT("Could not create '" ICD_UI_SHOW_CONNDLG_REQ "' message");
      goto reject;
    }

    if (new_request->attrs & ICD_POLICY_ATTRIBUTE_CONNECTIONS_FAILED)
      failed = TRUE;

    if (!dbus_message_append_args(message,
                                  DBUS_TYPE_BOOLEAN, &failed,
                                  DBUS_TYPE_INVALID))
    {
      ILOG_CRIT("Could not append args to '" ICD_UI_SHOW_CONNDLG_REQ "'");

      dbus_message_unref(message);
      goto reject;
    }

    data = g_new0(struct policy_ask_data, 1);
    data->private = private;
    data->new_request = new_request;
    data->policy_done_cb = policy_done_cb;
    data->policy_token = policy_token;
    *private = g_slist_prepend((GSList*)*private, data);

    ILOG_DEBUG("Requesting 'Select connection' dialog");

    data->pending = icd_dbus_send_system_mcall(message, 10000,
                                               show_conn_dlg_cb, data);
    dbus_message_unref(message);

    if (!data->pending)
    {
      policy_done_cb(ICD_POLICY_REJECTED, new_request, policy_token);
      *private = g_slist_remove((GSList *)*private, data);
      g_free(data);
    }
  }
  else
    policy_done_cb(ICD_POLICY_ACCEPTED, new_request, policy_token);

  return;

reject:
  policy_done_cb(ICD_POLICY_REJECTED, new_request, policy_token);
}

static void
icd_policy_ask_request_cancel(struct icd_policy_request *request,
                              gpointer *private)
{
  GSList *l;

  for (l = (GSList *)*private; l; l = l->next)
  {
    struct policy_ask_data *priv = (struct policy_ask_data *)l->data;

    if (priv)
    {
      struct icd_policy_request *new_request = priv->new_request;

      if ((request->network_attrs & ICD_NW_ATTR_LOCALMASK) ==
          (new_request->network_attrs & ICD_NW_ATTR_LOCALMASK) &&
          string_equal(request->network_type, new_request->network_type) &&
          string_equal(request->network_id, new_request->network_id) )
      {
        ILOG_DEBUG("Cancelling request %s/%0x/%s in policy iap ask",
                   request->network_type, request->network_attrs,
                   request->network_id);

        *(priv->private) = g_slist_remove((GSList *)*(priv->private), priv);
        dbus_pending_call_cancel(priv->pending);
        g_free(priv);
      }
    }
    else
      ILOG_ERR("policy iap ask data in list is NULL");
  }
}

void
icd_policy_init(struct icd_policy_api *policy_api,
                icd_policy_nw_add_fn add_network,
                icd_policy_request_merge_fn merge_requests,
                icd_policy_request_make_new_fn make_request,
                icd_policy_scan_start_fn scan_start,
                icd_policy_scan_stop_fn scan_stop,
                icd_policy_nw_close_fn nw_close,
                icd_policy_network_priority_fn priority,
                icd_policy_service_module_check_fn srv_check)
{
  policy_api->new_request = icd_policy_ask_request_new;
  policy_api->cancel_request = icd_policy_ask_request_cancel;
}
