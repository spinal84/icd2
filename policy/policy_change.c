#include <osso-ic-dbus.h>
#include <osso-ic-ui-dbus.h>
#include <osso-ic.h>

#include <string.h>

#include "icd_dbus.h"
#include "policy_api.h"
#include "icd_log.h"

#define POLICY_CHANGE_CALL_TIMEOUT 10 * 1000
#define POLICY_CHANGE_EXTRA_FILTER "member='" ICD_UI_CHANGE_SIG "'"

struct policy_change_data
{
  DBusPendingCall *change_call;
  gchar *change_from;
  gchar *change_to;
  gboolean is_changing;
  icd_policy_request_new_cb_fn done_cb;
  struct icd_policy_request *new_request;
  gpointer done_token;
};

static void
policy_change_delete_data(struct policy_change_data *data)
{
  if (data->change_call)
  {
    dbus_pending_call_cancel(data->change_call);
    data->change_call = NULL;
  }

  g_free(data->change_from);
  data->change_from = NULL;
  g_free(data->change_to);
  data->change_to = NULL;
}

static void
policy_change_do_cb(enum icd_policy_status status,
		    struct policy_change_data *data)
{
  icd_policy_request_new_cb_fn policy_done_cb = data->done_cb;

  policy_change_delete_data(data);

  if (policy_done_cb)
    policy_done_cb(status, data->new_request, data->done_token);
  else
    ILOG_WARN("policy change callback is missing so it is not called!");

  data->is_changing = FALSE;
  data->done_cb = NULL;
  data->new_request = NULL;
  data->done_token = NULL;
}

static DBusHandlerResult
policy_change_done(DBusConnection *connection,
		   DBusMessage *message,
		   void *user_data)
{
  if (dbus_message_is_signal(message, ICD_UI_DBUS_INTERFACE, ICD_UI_CHANGE_SIG))
  {
    struct policy_change_data *data = (struct policy_change_data *)user_data;
    dbus_bool_t accepted = FALSE;
    gchar *change_from;
    gchar *change_to;

    if (dbus_message_get_args(message, NULL,
                              DBUS_TYPE_STRING, &change_from,
                              DBUS_TYPE_STRING, &change_to,
                              DBUS_TYPE_BOOLEAN, &accepted,
                              DBUS_TYPE_INVALID))
    {
      if (data->change_from && data->change_to &&
          !strcmp(data->change_from, change_from) &&
          !strcmp(data->change_to, change_to))
      {
        ILOG_DEBUG("policy change from '%s' to '%s' %saccepted",
                   data->change_from, data->change_to,
                   accepted ? "" : "not ");
      }
      else
      {
        ILOG_ERR("policy change expected change from '%s' to '%s', "
		 "got '%s' and '%s'", data->change_from, data->change_to,
		 change_from, change_to);
      }
    }
    else
      ILOG_WARN("policy change could not get message args");

    policy_change_do_cb(
		  accepted ? ICD_POLICY_ACCEPTED : ICD_POLICY_REJECTED, data);
  }

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
policy_change_destruct(gpointer *private)
{
  struct policy_change_data *data = (struct policy_change_data *)*private;

  icd_dbus_disconnect_system_bcast_signal(ICD_UI_DBUS_INTERFACE,
					  policy_change_done, data,
					  POLICY_CHANGE_EXTRA_FILTER);
  policy_change_delete_data(data);
  g_free(data);
  *private = NULL;
}

static void
policy_change_confirm_cb(DBusPendingCall *pending, void *user_data)
{
  struct policy_change_data *data = (struct policy_change_data *)user_data;
  DBusMessage *message = dbus_pending_call_steal_reply(pending);

  dbus_pending_call_unref(data->change_call);
  data->change_call = NULL;

  if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR)
  {
    ILOG_INFO("policy change confirmation dialog rejected change "
	      "from '%s' to '%s'", data->change_from, data->change_to);
  }
  else
    ILOG_WARN("policy change dialog confirmed but actual dialog "
	      "not implemented; bug in dialogs!");

  policy_change_do_cb(ICD_POLICY_REJECTED, data);
  dbus_message_unref(message);
}

static gboolean
policy_change_confirm(struct policy_change_data *data)
{
  ILOG_DEBUG("policy change sending confirm");

  DBusMessage *message = dbus_message_new_method_call(ICD_UI_DBUS_SERVICE,
						      ICD_UI_DBUS_PATH,
						      ICD_UI_DBUS_INTERFACE,
						      ICD_UI_SHOW_CHANGE_REQ);
  if (message)
  {
    if (dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &data->change_from,
				 DBUS_TYPE_STRING, &data->change_to,
				 DBUS_TYPE_INVALID))
    {
      data->change_call = icd_dbus_send_system_mcall(
	  message, POLICY_CHANGE_CALL_TIMEOUT, policy_change_confirm_cb, data);
      data->is_changing = TRUE;
      return TRUE;
    }

    dbus_message_unref(message);
  }

  return FALSE;
}

static void
policy_change_new_request(struct icd_policy_request *new_request,
			  const GSList *existing_requests,
			  icd_policy_request_new_cb_fn policy_done_cb,
			  gpointer policy_token, gpointer *private)
{
  struct policy_change_data *data = (struct policy_change_data *)*private;
  guint policy_attrs;

  if (existing_requests)
  {
    struct icd_policy_request *request =
        (struct icd_policy_request *)existing_requests->data;

    if (new_request->attrs & ICD_POLICY_ATTRIBUTE_BACKGROUND)
    {
      ILOG_INFO("policy change not accepted for req %p "
		"with ICD_POLICY_ATTRIBUTE_BACKGROUND", new_request);
      policy_done_cb(ICD_POLICY_REJECTED, new_request, policy_token);
      return;
    }

    if (data->is_changing)
    {
      ILOG_INFO("policy change still processing previous change");
      policy_done_cb(ICD_POLICY_REJECTED, new_request, policy_token);
      return;
    }

    data->change_from = g_strdup(request->network_id);
    data->done_cb = policy_done_cb;
    data->done_token = policy_token;
    data->new_request = new_request;
    data->change_to = g_strdup(new_request->network_id);

    ILOG_INFO("policy change connection requested from '%s' to maybe '%s'",
              data->change_from, data->change_to);

    policy_attrs = new_request->attrs;

    if (policy_attrs & (ICD_POLICY_ATTRIBUTE_ALWAYS_ONLINE_CHANGE |
                        ICD_POLICY_ATTRIBUTE_CONN_UI))
    {
      ILOG_INFO("policy change from '%s' to maybe '%s'", data->change_from,
                data->change_to);
      policy_change_do_cb(ICD_POLICY_ACCEPTED, data);
    }
    else
    {
      if (policy_attrs & ICD_POLICY_ATTRIBUTE_NO_INTERACTION)
      {
        ILOG_INFO("policy change cannot ask for dialog "
		  "since ICD_POLICY_ATTRIBUTE_NO_INTERACTION set");
        policy_change_do_cb(ICD_POLICY_REJECTED, data);
        return;
      }
      else
	policy_change_confirm(data);

      if (!data->change_call)
      {
        ILOG_ERR("policy change cannot be confirmed, rejecting req %p",
                 new_request);
        policy_change_do_cb(ICD_POLICY_REJECTED, data);
      }
    }
  }
  else
    policy_done_cb(ICD_POLICY_ACCEPTED, new_request, policy_token);
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
  struct policy_change_data *data = g_new0(struct policy_change_data, 1);

  policy_api->new_request = policy_change_new_request;
  policy_api->private = data;
  policy_api->destruct = policy_change_destruct;
  icd_dbus_connect_system_bcast_signal(ICD_UI_DBUS_INTERFACE,
				       policy_change_done, data,
                                       POLICY_CHANGE_EXTRA_FILTER);
}
