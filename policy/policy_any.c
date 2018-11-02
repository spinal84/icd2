#include <gconf/gconf-client.h>
#include <osso-ic-gconf.h>
#include <osso-ic.h>

#include <string.h>

#include "policy_api.h"
#include "icd_log.h"

#define CHANGE_WHILE_CONNECTED_KEY ICD_GCONF_NETWORK_MAPPING \
                                         "/change_while_connected"
#define AUTO_CONNECT_KEY ICD_GCONF_NETWORK_MAPPING "/auto_connect"

struct policy_any_data
{
  icd_policy_nw_add_fn add_network;
  icd_policy_request_merge_fn merge;
  icd_policy_scan_start_fn scan_start;
  icd_policy_scan_stop_fn scan_stop;
  struct icd_policy_request *request;
  GSList *ongoing_scans;
  GSList *scan_types_list;
  gint min_prio;
  gboolean iaps_added;
  GSList *found_networks;
  icd_policy_service_module_check_fn srv_check;
};

struct policy_scan_data
{
  icd_policy_request_new_cb_fn policy_done_cb;
  gpointer policy_token;
  struct policy_any_data *any_data;
};

struct policy_any_network
{
  gchar *service_type;
  guint service_attrs;
  gchar *service_id;
  gchar *network_type;
  guint network_attrs;
  gchar *network_id;
  gint network_priority;
  enum icd_nw_levels signal;
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

static int
network_compare(struct policy_any_network *a, struct policy_any_network *b)
{
  int rv = b->network_priority - a->network_priority;

  if (rv == 0)
    rv = b->signal - a->signal;

  return rv;
}

static void
scan_cb(const guint status, const gchar *service_name,
        const gchar *service_type, const guint service_attrs,
        const gchar *service_id, gint service_priority,
        const gchar *network_name, const gchar *network_type,
        const guint network_attrs, const gchar *network_id,
        gint network_priority, const enum icd_nw_levels signal,
        gpointer user_data)
{
  struct policy_scan_data *scan_data = (struct policy_scan_data *)user_data;
  struct policy_any_data *data = scan_data->any_data;
  GSList *l;

  if (status == ICD_POLICY_SCAN_DONE)
  {
    ILOG_DEBUG("any connection scan complete for '%s', scan data %p",
               network_type, scan_data);
    scan_data->any_data->scan_stop(scan_cb, scan_data);
    data->ongoing_scans = g_slist_remove(data->ongoing_scans, scan_data);

    if (!data->ongoing_scans && !data->scan_types_list)
    {
      if (data->iaps_added)
      {
        ILOG_INFO("any connection found iaps");

        for (l = data->found_networks; l; l = l->next)
        {
          struct policy_any_network *network =
                                    (struct policy_any_network *)l->data;

          if (network)
          {
            if (data->request)
            {
              data->add_network(data->request, network->service_type,
                                network->service_attrs, network->service_id,
                                network->network_type, network->network_attrs,
                                network->network_id, network->network_priority);
            }
            else
              ILOG_DEBUG("request disappeared %p", scan_data->any_data);

            g_free(network->service_type);
            g_free(network->service_id);
            g_free(network->network_type);
            g_free(network->network_id);
            g_free(network);
          }
          else
            ILOG_ERR("any connection network is NULL");
        }

        g_slist_free(data->found_networks);
        data->found_networks = NULL;
      }
      else
        ILOG_INFO("any connection did not find any iaps");

      if (data->request)
      {
        if (data->iaps_added)
          data->request->attrs |= ICD_POLICY_ATTRIBUTE_HAS_CONNECTIONS;
        else
          data->request->attrs |= (ICD_POLICY_ATTRIBUTE_HAS_CONNECTIONS |
                                   ICD_POLICY_ATTRIBUTE_CONNECTIONS_FAILED);
      }

      data->iaps_added = FALSE;
      scan_data->policy_done_cb(ICD_POLICY_ACCEPTED, data->request,
                                scan_data->policy_token);
      scan_data->any_data->request = NULL;
    }

    g_free(scan_data);
  }
  else
  {
    if (!(network_attrs & ICD_NW_ATTR_AUTOCONNECT))
      return;

    if (status == ICD_POLICY_SCAN_NEW_NETWORK)
      goto new_net;

    for (l = data->found_networks; l; l = l->next)
    {
      struct policy_any_network *network = (struct policy_any_network *)l->data;

      if ((network->network_attrs & ICD_NW_ATTR_LOCALMASK) ==
          (network_attrs & ICD_NW_ATTR_LOCALMASK) &&
          string_equal(network->network_type, network_type) &&
          string_equal(network->network_id, network_id))
      {
        data->found_networks = g_slist_remove(data->found_networks, network);
        g_free(network->service_type);
        g_free(network->service_id);
        g_free(network->network_type);
        g_free(network->network_id);
        g_free(network);

        if (status != ICD_POLICY_SCAN_EXPIRED_NETWORK)
        {
new_net:
          if ((status == ICD_POLICY_SCAN_NEW_NETWORK ||
               status == ICD_POLICY_SCAN_UPDATE_NETWORK) &&
              scan_data->any_data->min_prio < network_priority)
          {
            struct policy_any_network *network =
                                       g_new0(struct policy_any_network, 1);

            network->service_type = g_strdup(service_type);
            network->service_attrs = service_attrs;
            network->service_id = g_strdup(service_id);
            network->network_type = g_strdup(network_type);
            network->network_attrs = network_attrs;
            network->network_id = g_strdup(network_id);
            network->network_priority = network_priority;
            network->signal = signal;
            data->found_networks =
                g_slist_insert_sorted(data->found_networks, network,
                                      (GCompareFunc)network_compare);
            scan_data->any_data->iaps_added = TRUE;
          }

          return;
        }
      }
    }

    ILOG_WARN("policy any could not find non-existent network %s/%0x/%s",
                network_type, network_attrs, network_id);
  }
}

static void
icd_policy_any_cancel_request(struct icd_policy_request *request,
                              gpointer *private)
{
  struct policy_any_data *data = (struct policy_any_data *)*private;

  if (!request || data->request == request)
  {
    GSList *l = data->ongoing_scans;

    for (l = data->ongoing_scans; l; l = l->next)
    {
      if (l->data)
      {
        ILOG_DEBUG("any connection stopping scan for %p, %p", scan_cb,
                   l->data);
        data->scan_stop(scan_cb, l->data);
        g_free(l->data);
      }
    }

    g_slist_free(data->ongoing_scans);
    data->ongoing_scans = NULL;

    for (l = data->found_networks; l; l = l->next)
    {
      struct policy_any_network *network = (struct policy_any_network *)l->data;

      if (network)
      {
        g_free(network->service_type);
        g_free(network->service_id);
        g_free(network->network_type);
        g_free(network->network_id);
        g_free(network);
      }
      else
        ILOG_ERR("any connection network is NULL");
    }

    g_slist_free(data->found_networks);
    data->found_networks = NULL;
    data->request = NULL;
  }
}

static void
icd_policy_any_destruct(gpointer *private)
{
  icd_policy_any_cancel_request(NULL, private);
  g_free(*private);
  *private = NULL;
}

static gint
get_max_priority(const GSList *existing_requests)
{
  GConfClient *gconf = gconf_client_get_default();
  gint rv = -1;

  if (gconf_client_get_bool(gconf, CHANGE_WHILE_CONNECTED_KEY, NULL))
  {
    const GSList *l;

    for (l = existing_requests; l; l = l->next)
    {
      struct icd_policy_request *request =
          (struct icd_policy_request *)l->data;

      if (request && rv < request->network_priority)
        rv = request->network_priority;
    }
  }

  g_object_unref(gconf);

  return rv;
}

static void
icd_policy_any_new_request(struct icd_policy_request *new_request,
                           const GSList *existing_requests,
                           icd_policy_request_new_cb_fn policy_done_cb,
                           gpointer policy_token, gpointer *private)
{
  struct policy_any_data *data = (struct policy_any_data *)*private;
  GSList *candidates;
  GConfClient *gconf;
  gboolean scan_started;
  GSList *iaps;
  char *type;
  GSList *scan_types_list_old;
  GSList *scan_types_list;
  GError *err = NULL;

  if (strcmp(new_request->network_id, OSSO_IAP_ANY))
  {
    policy_done_cb(ICD_POLICY_ACCEPTED, new_request, policy_token);
    return;
  }

  if (new_request->attrs & ICD_POLICY_ATTRIBUTE_HAS_CONNECTIONS)
  {
    ILOG_INFO("any connection request %p already has connections", new_request);
    policy_done_cb(ICD_POLICY_ACCEPTED, new_request, policy_token);
    return;
  }

  if (data->ongoing_scans)
  {
    GSList *l;

    for (l = data->ongoing_scans; l; l = l->next)
    {
      ILOG_ERR("any connection waiting for OSSO_IAP_ANY request %p scan_data %p reply",
               data->request->request_token, l->data);
    }

    policy_done_cb(ICD_POLICY_REJECTED, new_request, policy_token);

    return;
  }

  data->request = new_request;
  gconf = gconf_client_get_default();
  candidates = gconf_client_get_list(gconf, AUTO_CONNECT_KEY,
                                     GCONF_VALUE_STRING, NULL);
  scan_types_list = candidates;

  if (candidates)
  {
    char *p = candidates->data;

    if (p && !strcmp(p, "*"))
    {
      GSList *types;

      if (candidates->next)
        ILOG_WARN("any connection wildcard '*' allowed only by itself");

      do
      {
        g_free(scan_types_list->data);
        scan_types_list = g_slist_delete_link(scan_types_list, scan_types_list);
      }
      while (scan_types_list);

      types = gconf_client_all_dirs(gconf, ICD_GCONF_NETWORK_MAPPING, &err);

      if (err)
      {
        ILOG_WARN("any connection could not find network types for '*': %s",
                  err->message);
        g_clear_error(&err);
      }

      if (!types)
        goto skip;

      do
      {
        if (types->data)
        {
          p = g_strrstr((const gchar *)types->data, "/");

          if (p && p != (gchar *)-1)
          {
            if (!strcmp(p, "*"))
              ILOG_WARN("any connection wildcard '*' not allowed as network type name");
            else
            {
              scan_types_list =
                  g_slist_prepend(scan_types_list, g_strdup(p + 1));
            }
          }

          g_free(types->data);
        }

        types = g_slist_delete_link(types, types);
      }
      while (types);
    }
    else
    {
      GSList *l;

      for (l = candidates; l; l = l->next)
      {
        gchar *s = l->data;

        if (s && !strcmp(s, "*"))
        {
          ILOG_WARN("any connection wildcard '*' allowed only as first entry");
          g_free(s);
          scan_types_list = g_slist_delete_link(scan_types_list, l);
        }
      }
    }

    if (scan_types_list && g_slist_nth(scan_types_list, 0))
    {
      iaps = gconf_client_all_dirs(gconf, ICD_GCONF_PATH, NULL);

      if (iaps)
      {
        scan_types_list_old = scan_types_list;
        scan_types_list = NULL;

        do
        {
          gchar *s = g_strconcat((const gchar *)iaps->data, "/type", NULL);

          type = gconf_client_get_string(gconf, s, NULL);
          g_free(s);

          if (type)
          {
            GSList *l;

            for (l = scan_types_list_old; l; l = l->next)
            {
              s = (gchar *)l->data;

              if (!strcmp(s, type))
              {
                scan_types_list = g_slist_prepend(scan_types_list, s);
                scan_types_list_old = g_slist_delete_link(scan_types_list_old, l);
                ILOG_DEBUG("network type '%s' IAP '%s' found in gconf",
                           (char *)scan_types_list->data, (char *)iaps->data);
                break;
              }
            }
          }
          else
          {
            ILOG_ERR("Cannot find %s/type, your gconf is perhaps corrupted. Skipping this IAP.",
                     (char *)iaps->data);
          }

          g_free(type);
          g_free(iaps->data);
          iaps = g_slist_delete_link(iaps, iaps);
        }
        while (iaps);
      }
      else
      {
        scan_types_list_old = scan_types_list;
        scan_types_list = NULL;
      }

      while (scan_types_list_old)
      {
        if (data->srv_check((const gchar *)scan_types_list_old->data))
        {
          ILOG_DEBUG("service module found for network type '%s'",
                     (char *)scan_types_list_old->data);
          scan_types_list = g_slist_prepend(scan_types_list,
                                          scan_types_list_old->data);
        }
        else
        {
          ILOG_DEBUG("network type '%s' IAPs not found in gconf",
                     (char *)scan_types_list_old->data);
          g_free(scan_types_list_old->data);
        }

        scan_types_list_old = g_slist_delete_link(scan_types_list_old,
                                                scan_types_list_old);
      }
    }
  }

skip:
  g_object_unref(gconf);

  data->scan_types_list = scan_types_list;
  data->min_prio = get_max_priority(existing_requests);

  ILOG_DEBUG("any connection request %p scanning for networks with prio > %d",
             data->request->request_token, data->min_prio);

  scan_started = FALSE;

  while(data->scan_types_list)
  {
    gchar *type = (gchar *)data->scan_types_list->data;
    data->scan_types_list = g_slist_delete_link(data->scan_types_list,
                                              data->scan_types_list);

    if (type && *type)
    {
      struct policy_scan_data *scan_data;

      ILOG_DEBUG("any connection starting scan for '%s'", type);
      scan_data = g_new0(struct policy_scan_data, 1);
      scan_data->any_data = data;
      scan_data->policy_done_cb = policy_done_cb;
      scan_data->policy_token = policy_token;
      data->ongoing_scans = g_slist_prepend(data->ongoing_scans, scan_data);
      data->scan_start(type, ICD_NW_SEARCH_SCOPE_SAVED, scan_cb, scan_data);
      scan_started = TRUE;
    }

    g_free(type);
  }

  if (!scan_started)
  {
    new_request->attrs |= ICD_POLICY_ATTRIBUTE_HAS_CONNECTIONS;
    policy_done_cb(ICD_POLICY_ACCEPTED, new_request, policy_token);
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
  struct policy_any_data *data = g_new0(struct policy_any_data, 1);

  data->add_network = add_network;
  data->merge = merge_requests;
  data->scan_start = scan_start;
  data->scan_stop = scan_stop;
  data->srv_check = srv_check;

  policy_api->new_request = icd_policy_any_new_request;
  policy_api->cancel_request = icd_policy_any_cancel_request;
  policy_api->destruct = icd_policy_any_destruct;
  policy_api->private = data;
}
