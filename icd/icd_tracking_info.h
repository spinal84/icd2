#ifndef ICD_TRACKING_INFO_H
#define ICD_TRACKING_INFO_H

#include <glib.h>
#include <dbus/dbus.h>

enum icd_tracking_info_api {
  ICD_TRACKING_INFO_ICD,
  ICD_TRACKING_INFO_ICD2
};

struct icd_tracking_info {
  enum icd_tracking_info_api interface;
  gchar *sender;
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

#endif

