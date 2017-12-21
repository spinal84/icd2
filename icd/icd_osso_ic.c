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

/** milliseconds to wait for UI to respond to requests; used only for log
 * message printing for now
 */
#define ICD_OSSO_UI_REQUEST_TIMEOUT   4 * 1000

/** ip data structure */
struct icd_osso_ic_ipdata {
  /** how many times the callback has been called */
  guint has_called;

  /** how many times the callback will be called */
  guint howmany;

  /** D-Bus request */
  DBusMessage *request;
};

/** connection statistics */
struct icd_osso_ic_stats_data {
  /** method call for the statistics request */
  DBusMessage *request;

  /** time active */
  guint time_active;

  /** signal strength */
  enum icd_nw_levels signal;

  /** base station id */
  gchar *station_id;

  /** raw signal strength */
  gint dB;

  /** received packets */
  guint rx_packets;

  /** sent packets */
  guint tx_packets;

  /** received bytes */
  guint rx_bytes;

  /** sent bytes */
  guint tx_bytes;
};

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

static gpointer
icd_osso_ic_ipinfo_get_first(struct icd_request *request, gpointer user_data)
{
  if (request->state != ICD_REQUEST_SUCCEEDED || !request->try_iaps)
  {
    ILOG_DEBUG("request %p not in ICD_REQUEST_SUCCEEDED state", request);
    return NULL;
  }

  ILOG_DEBUG("querying ip info from request %p", request);

  if (request->try_iaps->data)
    return request->try_iaps->data;

  ILOG_CRIT("request %p in ICD_REQUEST_SUCCEEDED state but NULL iap", request);

  return NULL;
}

static void
icd_osso_ic_connstats_error(DBusMessage *method_call)
{
  DBusMessage *msg = dbus_message_new_error(method_call,
                                            ICD_DBUS_ERROR_IAP_NOT_AVAILABLE,
                                            "IAP does not exist anymore");

  icd_dbus_send_system_msg(msg);
  dbus_message_unref(msg);
}
static void
icd_osso_ic_ipinfo_cb(gpointer addr_info_cb_token, const gchar *network_type,
                      const guint network_attrs, const gchar *network_id,
                      gchar *ip_address, gchar *ip_netmask, gchar *ip_gateway,
                      gchar *ip_dns1, gchar *ip_dns2, gchar *ip_dns3)
{
  struct icd_osso_ic_ipdata *data =
      (struct icd_osso_ic_ipdata *)addr_info_cb_token;

  if (!data)
  {
    ILOG_ERR("ip addr info returned NULL ipdata");
    return;
  }

  if (!data->request)
  {
    ILOG_DEBUG("ip info called %d time(s), reply already sent, but that's ok",
               data->has_called + 1);
  }
  else
  {
    struct icd_iap *iap = icd_iap_find(network_type, network_attrs, network_id);

    if (!iap)
    {
      ILOG_WARN("ip stats cannot find iap %s/%0x/%s anymore, but that's ok",
                network_type, network_attrs, network_id);
      icd_osso_ic_connstats_error(data->request);
    }
    else
    {
      DBusMessage *msg;

      if (!ip_address)
        ip_address = "";

      if (!ip_netmask)
        ip_netmask = "";

      if (!ip_gateway)
        ip_gateway = "";

      if (!ip_dns1)
        ip_dns1 = "";

      if (!ip_dns2)
        ip_dns2 = "";

      msg = dbus_message_new_method_return(data->request);

      if (msg)
      {
        if (dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &network_id,
                                     DBUS_TYPE_STRING, &ip_address,
                                     DBUS_TYPE_STRING, &ip_netmask,
                                     DBUS_TYPE_STRING, &ip_gateway,
                                     DBUS_TYPE_STRING, &ip_dns1,
                                     DBUS_TYPE_STRING, &ip_dns2,
                                     DBUS_TYPE_INVALID))
        {
          ILOG_DEBUG("Returning IP info %s/%s %s %s/%s for iap %p", ip_address,
                     ip_netmask, ip_gateway, ip_dns1, ip_dns2, iap);
        }
        else
        {
          dbus_message_unref(msg);
          msg = NULL;
        }
      }

      if (!msg)
      {
        msg = dbus_message_new_error(
              data->request, DBUS_ERROR_NO_MEMORY,
              "Could not create get_ipinfo method call reply");
      }

      if (msg)
      {
        icd_dbus_send_system_msg(msg);
        dbus_message_unref(msg);
      }
      else
        ILOG_CRIT("Could not create get_ipinfo method call error reply");
    }

    ILOG_DEBUG("ip data called for the first time (%d)", data->has_called + 1);
    dbus_message_unref(data->request);
    data->request = NULL;
  }

  data->has_called++;

  if (data->has_called == data->howmany)
  {
    ILOG_DEBUG("ip info deleted ipdata %p in callback", data);
    g_free(data);
  }
}

static DBusMessage *
icd_osso_ic_ipinfo(DBusMessage *method_call, void *user_data)
{
  struct icd_osso_ic_ipdata *data = g_new0(struct icd_osso_ic_ipdata, 1);
  struct icd_iap *iap =
      (struct icd_iap *)icd_request_foreach(icd_osso_ic_ipinfo_get_first, data);

  if (!iap)
  {
    ILOG_INFO("no ipv4 info available");
    g_free(data);
    return dbus_message_new_error(method_call,
                                  ICD_DBUS_ERROR_IAP_NOT_AVAILABLE,
                                  "No active IAP");
  }

  dbus_message_ref(method_call);
  data->request = method_call;

  ILOG_DEBUG("requesting ip info from %p", iap);

  data->howmany = icd_iap_get_ipinfo(iap, icd_osso_ic_ipinfo_cb, data);
  ILOG_DEBUG("ipinfo says %d cbs expected, has called %d", data->howmany,
             data->has_called);

  if (data->howmany == data->has_called)
  {
    /*
      fmg - something's fishy there or I am too stupid to get it:
      the same condition exists at the end of icd_osso_ic_ipinfo_cb, I hope it
      would not lead to double-free of data struct
     */
    ILOG_DEBUG("ip info deleted ipdata %p", data);

    if (data->request)
    {
      dbus_message_unref(data->request);
      data->request = NULL;
    }

    g_free(data);
  }

  return NULL;
}

/** OSSO IC API method call handlers */
static struct icd_osso_ic_handler icd_osso_ic_htable[] = {
/*  {ICD_DBUS_INTERFACE, ICD_ACTIVATE_REQ, "s", icd_osso_ic_activate},
  {ICD_DBUS_INTERFACE, ICD_SHUTDOWN_REQ, "", icd_osso_ic_shutdown},*/
  {ICD_DBUS_INTERFACE, ICD_CONNECT_REQ, "su", icd_osso_ic_connect},
  /*{ICD_DBUS_INTERFACE, ICD_DISCONNECT_REQ, "s", icd_osso_ic_disconnect},*/
  {ICD_DBUS_INTERFACE, ICD_GET_IPINFO_REQ, "", icd_osso_ic_ipinfo},
  /*{ICD_DBUS_INTERFACE, ICD_GET_STATISTICS_REQ, "", icd_osso_ic_connstats},
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

static void
icd_osso_ic_ui_pending(DBusPendingCall *pending, void *user_data)
{
  struct icd_osso_ic_mcall_data *data =
      (struct icd_osso_ic_mcall_data *)user_data;
  DBusMessage *reply;
  gboolean success = FALSE;

  reply = dbus_pending_call_steal_reply(pending);

  if (data->pending_call)
  {
    dbus_pending_call_unref(data->pending_call);
    data->pending_call = NULL;
  }

  if (dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR )
    success = TRUE;

  if (success)
    ILOG_DEBUG("'%s' successfully requested from UI", data->mcall_name);
  else
  {
    ILOG_DEBUG("'%s' requested from UI but returned: '%s'", data->mcall_name,
               dbus_message_get_error_name(reply));
  }

  if (data->cb)
  {
    ILOG_DEBUG("icd UI callback %p called with success '%d' user data %p",
               data->cb, success, data->user_data);
    data->cb(success, data->user_data);
  }
  else
    ILOG_DEBUG("icd UI callback NULL");

  g_free(data);
}

void
icd_osso_ui_send_retry(const gchar *iap_name, const gchar *error,
                       icd_osso_ui_cb_fn cb, gpointer user_data)
{
  struct icd_osso_ic_mcall_data *mcall_data;
  DBusMessage *mcall;
  DBusPendingCall *pending;

  mcall_data = g_new0(struct icd_osso_ic_mcall_data, 1);
  mcall_data->user_data = user_data;
  mcall_data->cb = cb;
  mcall_data->mcall_name = ICD_UI_SHOW_RETRY_REQ;
  mcall = dbus_message_new_method_call(ICD_UI_DBUS_SERVICE,
                                       ICD_UI_DBUS_PATH,
                                       ICD_UI_DBUS_INTERFACE,
                                       ICD_UI_SHOW_RETRY_REQ);
  if (mcall)
  {
    if (dbus_message_append_args(mcall,
                                 DBUS_TYPE_STRING, &iap_name,
                                 DBUS_TYPE_STRING, &error,
                                 DBUS_TYPE_INVALID))
    {
      pending = icd_dbus_send_system_mcall(mcall, ICD_OSSO_UI_REQUEST_TIMEOUT,
                                           icd_osso_ic_ui_pending, mcall_data);
      mcall_data->pending_call = pending;

      if (pending)
      {
        dbus_message_unref(mcall);
        return;
      }

      ILOG_WARN("icd UI mcall '%s' could not be sent", mcall_data->mcall_name);
    }
    else
      ILOG_ERR("could not append args to '%s' request", mcall_data->mcall_name);

    dbus_message_unref(mcall);
  }
  else
    ILOG_ERR("could not create '%s' request", mcall_data->mcall_name);

  if (mcall_data->cb)
    mcall_data->cb(FALSE, mcall_data->user_data);

  g_free(mcall_data);
}

void
icd_osso_ic_send_ack(GSList *tracking_list, const gchar *iap_name)
{
  GSList *l;

  if (!iap_name)
  {
    ILOG_CRIT("no iap name when sending ack");
    return;
  }

  for (l = tracking_list; l; l = l->next)
  {
    struct icd_tracking_info *track = (struct icd_tracking_info *)l->data;
    DBusMessage *msg;

    if (!track->request || track->interface)
      continue;

    msg = dbus_message_new_method_return(track->request);

    if (msg)
    {
      if (dbus_message_append_args(msg, DBUS_TYPE_STRING, &iap_name, 0))
      {
        ILOG_INFO("Sending ack for iap '%s' to '%s'", iap_name, track->sender);

        icd_dbus_send_system_msg(msg);
        dbus_message_unref(track->request);
        track->request = NULL;
      }
      else
      {
        ILOG_CRIT("failed to append arg to ack for '%s' request %p",
                  track->sender, track->request);
      }

      dbus_message_unref(msg);
    }
    else
    {
      ILOG_CRIT("failed to create ack for '%s' for request %p", track->sender,
                track->request);
    }
  }
}

gpointer
icd_osso_ui_send_save(const gchar *iap_name, icd_osso_ui_cb_fn cb,
                      gpointer user_data)
{
  struct icd_osso_ic_mcall_data *mcall_data;
  DBusMessage *message;
  DBusPendingCall *pending_call;

  mcall_data = g_new0(struct icd_osso_ic_mcall_data, 1);
  mcall_data->cb = cb;
  mcall_data->user_data = user_data;
  mcall_data->mcall_name = ICD_UI_SHOW_SAVEDLG_REQ;

  message = dbus_message_new_method_call(ICD_UI_DBUS_SERVICE,
                                         ICD_UI_DBUS_PATH,
                                         ICD_UI_DBUS_INTERFACE,
                                         ICD_UI_SHOW_SAVEDLG_REQ);
  if (message)
  {
    if (dbus_message_append_args(message,
                                 DBUS_TYPE_STRING, &iap_name,
                                 DBUS_TYPE_INVALID))
    {
      pending_call = icd_dbus_send_system_mcall(message,
                                                ICD_OSSO_UI_REQUEST_TIMEOUT,
                                                icd_osso_ic_ui_pending,
                                                mcall_data);
      mcall_data->pending_call = pending_call;

      if (pending_call)
      {
        dbus_message_unref(message);
        return mcall_data;
      }

      ILOG_WARN("icd UI mcall '%s' could not be sent", mcall_data->mcall_name);
    }
    else
      ILOG_ERR("could not append args to '%s' request", mcall_data->mcall_name);

    dbus_message_unref(message);
  }
  else
    ILOG_ERR("could not create '%s' request", mcall_data->mcall_name);

  if (mcall_data->cb)
    mcall_data->cb(FALSE, mcall_data->user_data);

  g_free(mcall_data);

  return NULL;
}
