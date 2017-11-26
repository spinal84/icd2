#include <string.h>
#include <dbus/dbus.h>
#include <gconf/gconf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <osso-ic-ui-dbus.h>
#include <osso-ic.h>
#include <osso-ic-dbus.h>
#include <icd_osso_ic.h>
#include "icd_dbus.h"
#include "icd_log.h"
#include "icd_gconf.h"
#include "network_api.h"
#include "icd_iap.h"
#include "icd_request.h"
#include "icd_tracking_info.h"
#include "icd_status.h"
#include "icd_wlan_defs.h"

/**
 * @brief Callback function called when a UI retry or save request has
 * completed
 *
 * @param success TRUE on success, FALSE on failure
 * @param user_data user data passed to retry or save function
 *
 */
typedef void(* icd_osso_ui_cb_fn)(gboolean success, gpointer user_data) ;

/** Callback data passed for UI method calls */
struct icd_osso_ic_mcall_data {
  /** pending call, if needed */
  DBusPendingCall *pending_call;

  /** method call name */
  gchar *mcall_name;

  /** callback */
  icd_osso_ui_cb_fn cb;

  /** user_data */
  gpointer user_data;
};

/**
 * @brief Function that handles an incoming OSSO IC API request
 *
 * @param request the D-Bus message
 * @param user_data user data
 *
 * @return the D-Bus reply or NULL if a reply is sent later
 *
 */
typedef DBusMessage*(* icd_osso_ic_message_handler)(DBusMessage *request, void *user_data);

/** Structure containing information to match a D-Bus message with the correct
 * handler function
 */
struct icd_osso_ic_handler {
  /**  D-Bus interface */
  const char *interface;

  /** D-Bus method */
  const char *method;

  /** D-Bus message signature */
  const char *signature;

  /** function handling this method call */
  icd_osso_ic_message_handler handler;
};

struct icd_osso_ic_get_state_data
{
  const char *sender;
  guint connections;
};

static gchar *
icd_osso_ic_get_type(const gchar *iap_name)
{
  return icd_gconf_get_iap_string(iap_name, ICD_GCONF_IAP_TYPE);
}

static DBusMessage *
icd_osso_ic_make_request(struct icd_request *merge_request,
                         struct icd_tracking_info *track, DBusMessage *message,
                         const gchar *requested_iap, const guint flags)
{
  guint network_attrs = ICD_NW_ATTR_IAPNAME;
  struct icd_request *request;
  gchar *network_type = NULL;

  if (strcmp("[ANY]", requested_iap) && strcmp("[ASK]", requested_iap))
  {
    network_type = icd_osso_ic_get_type(requested_iap);

    if (!network_type)
    {
      ILOG_ERR("network type cannot be NULL for requested iap '%s'", requested_iap);
      return dbus_message_new_error(message, ICD_DBUS_ERROR_INVALID_IAP,
                                    "IAP type not found in gconf");
    }

    if (icd_wlan_defs_is_wlan(network_type))
      network_attrs |= icd_wlan_defs_get_secmode(requested_iap);
  }

  request = icd_request_new(flags, NULL, 0, NULL, network_type, network_attrs,
                            requested_iap);

  if (merge_request)
    icd_request_merge(merge_request, request);

  if (track)
    icd_request_tracking_info_add(request, track);

  icd_request_make(request);
  g_free(network_type);

  return NULL;
}

static DBusMessage *
icd_osso_ic_connect(DBusMessage *method_call, void *user_data)
{
  DBusMessage *msg;

  if (dbus_message_get_type(method_call) == DBUS_MESSAGE_TYPE_METHOD_CALL)
  {
    struct icd_tracking_info *track;
    DBusError error;
    guint flags;
    gchar *iap;

    dbus_error_init(&error);
    dbus_message_get_args(method_call, &error,
                          DBUS_TYPE_STRING, &iap,
                          DBUS_TYPE_UINT32, &flags,
                          DBUS_TYPE_INVALID);
    dbus_error_free(&error);

    if (flags & OSSO_IAP_TIMED_CONNECT)
    {
      flags = ICD_POLICY_ATTRIBUTE_BACKGROUND |
          ICD_POLICY_ATTRIBUTE_NO_INTERACTION;
    }
    else
      flags = 0;

    track = icd_tracking_info_new(ICD_TRACKING_INFO_ICD,
                                  dbus_message_get_sender(method_call),
                                  method_call);

    msg = icd_osso_ic_make_request(NULL, track, method_call, iap, flags);
  }
  else
  {
    ILOG_ERR("message to 'connect' is not a method call");
    msg = dbus_message_new_error(method_call, DBUS_ERROR_NOT_SUPPORTED,
                                 "Message is not a method call");
  }

  return msg;
}

static DBusMessage *
icd_osso_ic_bg_killed(DBusMessage *method_call, void *user_data)
{
  gchar *s;
  struct icd_tracking_info *track;
  const gchar *sender;
  const gchar *application;

  dbus_message_get_args(method_call, NULL,
                        DBUS_TYPE_STRING, &application,
                        DBUS_TYPE_STRING, &sender,
                        DBUS_TYPE_INVALID);

  s = g_strdup_printf("com.nokia.%s", application);
  track = icd_tracking_info_find(sender);

  if (track)
  {
    ILOG_INFO("application '%s' ('%s') background killed", application, sender);

    icd_tracking_info_update(track, s, NULL);
  }
  else
  {
    ILOG_DEBUG("application '%s' ('%s') background killed but not tracked",
               application, sender);
  }

  g_free(s);

  return dbus_message_new_method_return(method_call);
}

static gpointer
icd_osso_ic_get_state_foreach(struct icd_request *request, gpointer user_data)
{
  struct icd_osso_ic_get_state_data *state_data;
  struct icd_iap *iap;

  state_data = (struct icd_osso_ic_get_state_data *)user_data;

  if (request->try_iaps)
  {
    ILOG_DEBUG("querying connection state for request %p", request);

    iap = (struct icd_iap *)request->try_iaps->data;

    if (iap)
    {
      switch ( iap->state )
      {
        case ICD_IAP_STATE_SCRIPT_PRE_UP:
        case ICD_IAP_STATE_LINK_UP:
        case ICD_IAP_STATE_LINK_POST_UP:
        case ICD_IAP_STATE_IP_UP:
        case ICD_IAP_STATE_SCRIPT_POST_UP:
        case ICD_IAP_STATE_SAVING:
          icd_status_connect(iap, state_data->sender, NULL);
          state_data->connections++;
          return NULL;
        case ICD_IAP_STATE_SRV_UP:
          if (iap->limited_conn)
            icd_status_limited_conn(iap, state_data->sender, NULL);
          else
            icd_status_connect(iap, state_data->sender, NULL);
          break;
        case ICD_IAP_STATE_CONNECTED:
          icd_status_connected(iap, state_data->sender, NULL);
          break;
        case ICD_IAP_STATE_CONNECTED_DOWN:
        case ICD_IAP_STATE_SRV_DOWN:
        case ICD_IAP_STATE_IP_DOWN:
        case ICD_IAP_STATE_LINK_PRE_DOWN:
        case ICD_IAP_STATE_LINK_DOWN:
        case ICD_IAP_STATE_SCRIPT_POST_DOWN:
          icd_status_disconnect(iap, state_data->sender, NULL);
          break;
        default:
          return NULL;
      }

      state_data->connections++;
    }
    else
      ILOG_CRIT("request %p, NULL iap", request);
  }
  else
    ILOG_DEBUG("request %p does not have any IAPs", request);

  return NULL;
}

static DBusMessage *
icd_osso_ic_get_state(DBusMessage *method_call, void *user_data)
{
  struct icd_osso_ic_get_state_data *state_data;
  DBusMessage *msg;

  state_data = g_new0(struct icd_osso_ic_get_state_data, 1);
  state_data->sender = dbus_message_get_sender(method_call);
  icd_request_foreach(icd_osso_ic_get_state_foreach, state_data);

  ILOG_INFO("connection state for %d connections sent",
            state_data->connections);

  msg = dbus_message_new_method_return(method_call);
  dbus_message_append_args(msg,
                           DBUS_TYPE_UINT32, &state_data->connections,
                           DBUS_TYPE_INVALID);
  g_free(state_data);

  return msg;
}

/** OSSO IC API method call handlers */
static struct icd_osso_ic_handler icd_osso_ic_htable[] = {
/*  {ICD_DBUS_INTERFACE, ICD_ACTIVATE_REQ, "s", icd_osso_ic_activate},
  {ICD_DBUS_INTERFACE, ICD_SHUTDOWN_REQ, "", icd_osso_ic_shutdown},*/
  {ICD_DBUS_INTERFACE, ICD_CONNECT_REQ, "su", icd_osso_ic_connect},
  /*{ICD_DBUS_INTERFACE, ICD_DISCONNECT_REQ, "s", icd_osso_ic_disconnect},
  {ICD_DBUS_INTERFACE, ICD_GET_IPINFO_REQ, "", icd_osso_ic_ipinfo},
  {ICD_DBUS_INTERFACE, ICD_GET_STATISTICS_REQ, "", icd_osso_ic_connstats},
  {ICD_DBUS_INTERFACE, ICD_GET_STATISTICS_REQ, "s", icd_osso_ic_connstats},*/
  {ICD_DBUS_INTERFACE, ICD_GET_STATE_REQ, "", icd_osso_ic_get_state},
  {ICD_DBUS_INTERFACE, "background_killing_application", "ss",
   icd_osso_ic_bg_killed},
  {NULL}
};

static DBusMessage *
icd_osso_ui_disconnect(DBusMessage *signal, void *user_data)
{
  DBusError error;
  dbus_bool_t disconnect_pressed;

  dbus_error_init(&error);
  dbus_message_get_args(signal, &error,
                        DBUS_TYPE_BOOLEAN, &disconnect_pressed,
                        DBUS_TYPE_INVALID);

  dbus_error_free(&error);

  if (disconnect_pressed)
  {
    GSList *request_list = icd_context_get()->request_list;
    struct icd_request *request;

    if (request_list)
      request = (struct icd_request *)request_list->data;
    else
      request = NULL;

    if (request)
    {
      ILOG_INFO("disconnect selected for '%s.%s', disconnecting request %p",
                dbus_message_get_interface(signal),
                dbus_message_get_member(signal), request);

      icd_request_cancel(request, ICD_POLICY_ATTRIBUTE_CONN_UI);
    }
    else
    {
      ILOG_WARN("disconnect selected for '%s.%s', but no requests",
                dbus_message_get_interface(signal),
                dbus_message_get_member(signal));
    }
  }
  else
  {
    ILOG_INFO("cancel selected for '%s.%s'", dbus_message_get_interface(signal),
              dbus_message_get_member(signal));
  }

  return NULL;
}

static DBusMessage *
icd_osso_ui_save(DBusMessage *signal, void *user_data)
{
  gchar *network_type;
  struct icd_iap *iap;
  DBusError error;
  gchar *name;
  gchar *iap_name;

  dbus_error_init(&error);
  dbus_message_get_args(signal, &error,
                        DBUS_TYPE_STRING, &iap_name,
                        DBUS_TYPE_STRING, &name,
                        DBUS_TYPE_INVALID);
  dbus_error_free(&error);
  network_type = icd_osso_ic_get_type(iap_name);
  iap = icd_iap_find(network_type, ICD_NW_ATTR_IAPNAME, iap_name);

  if (iap)
  {
    if (icd_iap_rename(iap, name))
      ILOG_DEBUG("Saved '%s' as '%s'", iap_name, name);
    else
      ILOG_WARN("IAP '%s' was not renamed", iap_name);
  }
  else
    ILOG_WARN("IAP '%s' not found when save signal received", iap_name);

  g_free(network_type);

  return NULL;
}

/** UI signal handlers */
static struct icd_osso_ic_handler icd_osso_ui_htable[] = {
  {ICD_UI_DBUS_INTERFACE, ICD_UI_DISCONNECT_SIG, "b",
   icd_osso_ui_disconnect},
/*  {ICD_UI_DBUS_INTERFACE, ICD_UI_RETRY_SIG, "sb", icd_osso_ui_retry},
  {ICD_UI_DBUS_INTERFACE, ICD_UI_RETRY_SIG, "sbb", icd_osso_ui_retry},*/
  {ICD_UI_DBUS_INTERFACE, ICD_UI_SAVE_SIG, "ss", icd_osso_ui_save},
  {NULL}
};

static icd_osso_ic_message_handler
icd_osso_ic_find_handler(DBusMessage *msg, struct icd_osso_ic_handler *handlers)
{
  const char *iface = dbus_message_get_interface(msg);
  const char *member = dbus_message_get_member(msg);

  while (handlers->interface)
  {
    if (!strcmp(iface, handlers->interface) &&
        !strcmp(member, handlers->method) &&
        (!handlers->signature ||
         dbus_message_has_signature(msg, handlers->signature)))
    {
      return handlers->handler;
    }

    handlers++;
  }

  return NULL;
}

static DBusHandlerResult
icd_osso_ic_request(DBusConnection *connection, DBusMessage *message,
                    void *user_data)
{
  icd_osso_ic_message_handler handler;
  DBusMessage *msg;

  handler = icd_osso_ic_find_handler(message, icd_osso_ic_htable);

  if (handler)
  {
    ILOG_INFO("Received %s.%s (%s) request",
              dbus_message_get_interface(message),
              dbus_message_get_member(message),
              dbus_message_get_signature(message));

    msg = handler(message, user_data);
  }
  else
  {
    ILOG_INFO("received '%s.%s' request is not recognized",
              dbus_message_get_interface(message),
              dbus_message_get_member(message));

    msg = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED,
                                 "Unsupported interface or method");
  }

  if (msg)
  {
    icd_dbus_send_system_msg(msg);
    dbus_message_unref(msg);
  }

  return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
icd_osso_ui_signal(DBusConnection *connection, DBusMessage *message,
                   void *user_data)
{
  if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL)
  {
    if (!strcmp(ICD_UI_DBUS_INTERFACE, dbus_message_get_interface(message)))
    {
      icd_osso_ic_message_handler handler =
          icd_osso_ic_find_handler(message, icd_osso_ui_htable);

      if (handler)
      {
        ILOG_INFO("received '%s.%s' (%s) signal from UI",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_signature(message));

        handler(message, user_data);
      }
      else
      {
        ILOG_ERR("received '%s.%s' (%s) request is not recognized",
                 dbus_message_get_interface(message),
                 dbus_message_get_member(message),
                 dbus_message_get_signature(message));
      }
    }
  }

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

gboolean
icd_osso_ic_init(struct icd_context *icd_ctx)
{
  if (!icd_dbus_register_system_service(ICD_DBUS_PATH,
                                        ICD_DBUS_SERVICE,
                                        DBUS_NAME_FLAG_REPLACE_EXISTING |
                                        DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                        icd_osso_ic_request,
                                        NULL))
  {
    ILOG_CRIT("could not register '" ICD_DBUS_SERVICE "'");
    return FALSE;
  }

  ILOG_DEBUG("listening on '" ICD_DBUS_SERVICE "'");

  if (!icd_dbus_connect_system_bcast_signal(ICD_UI_DBUS_INTERFACE,
                                            icd_osso_ui_signal, NULL, NULL))
  {
    ILOG_CRIT("could not connect to '" ICD_DBUS_PATH "'");

    icd_dbus_unregister_system_service(ICD_DBUS_PATH,
                                       ICD_DBUS_SERVICE);
    return FALSE;
  }

  ILOG_DEBUG("listening for '" ICD_DBUS_PATH "' messages ");

  return TRUE;
}

void
icd_osso_ic_deinit(void)
{
  icd_dbus_unregister_system_service(ICD_DBUS_PATH, ICD_DBUS_SERVICE);
  icd_dbus_disconnect_system_bcast_signal(ICD_UI_DBUS_INTERFACE,
                                          icd_osso_ui_signal, NULL, NULL);
}

void
icd_osso_ui_send_save_cancel(gpointer send_save_token)
{
  DBusPendingCall **pending = (DBusPendingCall **)send_save_token;

  if (pending && *pending)
  {
    dbus_pending_call_cancel(*pending);
    g_free(pending);
  }
}

void
icd_osso_ic_send_nack(GSList *tracking_list)
{
  GSList *l;

  for (l = tracking_list; l; l = l->next)
  {
    struct icd_tracking_info *track = (struct icd_tracking_info *)l->data;

    if (track->interface == ICD_TRACKING_INFO_ICD )
    {
      if (track->request)
      {
        DBusMessage *msg =
            dbus_message_new_error(track->request,
                                   ICD_DBUS_ERROR_IAP_NOT_AVAILABLE,
                                   "Failed to establish requested IAP");

        if (msg)
        {
          ILOG_INFO("Sending nack to '%s'", track->sender);

          icd_dbus_send_system_msg(msg);
          dbus_message_unref(msg);
        }
        else
        {
          ILOG_CRIT("failed to create nack for '%s' for request %p",
                    track->sender, track->request);
        }

        dbus_message_unref(track->request);
        track->request = NULL;
      }

      g_free(track->sender);
      g_free(track);
      l->data = NULL;
    }
  }
}
