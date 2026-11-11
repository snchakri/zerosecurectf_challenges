#ifndef FLAG_H
#define FLAG_H

#include <stdbool.h>

#include "wallet.h"

#define FLAG_PRICE 9999999L

bool flag_can_unlock(const wallet_t *wallet);
const char *flag_value(void);

#endif
