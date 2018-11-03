#ifndef ICD_TRACKING_INFO_H
#define ICD_TRACKING_INFO_H

/**
@file icd_tracking_info.h

@copyright GNU GPLv2 or later

@addtogroup icd_tracking_info Tracking of D-Bus users for a request

@ingroup internal

 * @{ */

#include <glib.h>
#include <dbus/dbus.h>

/** which D-Bus interface the tracking info is for */
enum icd_tracking_info_api {
  /** old icd API */
  ICD_TRACKING_INFO_ICD,
  /** new icd2 API */
  ICD_TRACKING_INFO_ICD2
};

/** Tracking info for D-Bus users. Needed for creating a reply to
 * ICD_CONNECT_REQ and possible future user reference counting */
struct icd_tracking_info {
  enum icd_tracking_info_api interface;

  /** D-Bus sender */
  gchar *sender;

  /** D-Bus message that needs a reply */
  DBusMessage *request;
};

struct icd_tracking_info *icd_tracking_info_find (const gchar *sender);

void icd_tracking_info_free (struct icd_tracking_info *track);
struct icd_tracking_info *
icd_tracking_info_new (enum icd_tracking_info_api interface,
                       const gchar *sender,
                       DBusMessage *message);
gboolean icd_tracking_info_update (struct icd_tracking_info *track,
                                   const gchar *sender,
                                   DBusMessage *message);

/** @} */

#endif

