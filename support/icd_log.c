#include "icd_log.h"

static enum icd_loglevel loglevel = ICD_INFO;

void
icd_log_open(void)
{
  DLOG_OPEN(PACKAGE " " VERSION);
}

void
icd_log_close(void)
{
  closelog();
}

enum icd_loglevel
icd_log_get_level(void)
{
  return loglevel;
}

enum icd_loglevel
    icd_log_set_level(enum icd_loglevel new_level)
{
  enum icd_loglevel old_level;

  if (new_level >= ICD_CRIT)
    new_level = ICD_CRIT;

  old_level = loglevel;
  loglevel = new_level;

  return old_level;
}

void
icd_log_nextlevel(void)
{
  if (loglevel)
    loglevel--;
  else
    loglevel = ICD_CRIT;

  syslog(30, "Log level set to %d", loglevel);
}
