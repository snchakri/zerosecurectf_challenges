#ifndef WALLET_H
#define WALLET_H

#include <stdbool.h>

#include "shop.h"

typedef struct {
    long balance;
    unsigned int transaction_count;
} wallet_t;

void wallet_init(wallet_t *wallet);
bool wallet_try_purchase(wallet_t *wallet, item_t *item, int quantity, int *total_cost);
void wallet_print_details(const wallet_t *wallet);

#endif
