#ifndef ICD_SETTINGS_BACKEND_H
#define ICD_SETTINGS_BACKEND_H

#include "icd_settings.h"

struct icd_settings {
  GHashTable *network_id;
};

gboolean icd_settings_add_handle (struct icd_settings *settings,
                                  icd_settings_handle handle);

#endif
