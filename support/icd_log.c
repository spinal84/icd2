#include "icd_log.h"

void icd_log_open()
{
  openlog("icd2 0.87+fremantle10+0m5", 9, 24);
}
