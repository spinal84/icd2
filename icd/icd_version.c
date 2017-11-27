#include <stdlib.h>
#include "icd_version.h"
#include "icd_log.h"

int
icd_version_compare(const char *a, const char *b)
{
  int rv;
  char *enda = NULL;
  char *endb = NULL;

  while (1)
  {
    int al = strtol(a, &enda, 10);
    int bl = strtol(b, &endb, 10);

    a = enda + 1;
    b = endb + 1;
    rv = al - bl;

    if (rv)
      break;

    if (!*enda)
    {
      if (*endb)
        return -1;
      else
        return 0;
    }

    if (!*endb)
      return 1;
  }

  return rv;
}
