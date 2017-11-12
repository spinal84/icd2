#ifndef ICD_SIGNAL_H
#define ICD_SIGNAL_H

typedef void (*icd_signal_handler_fn) (int sig);

int icd_signal_init (icd_signal_handler_fn signal_handler, ...);

#endif
