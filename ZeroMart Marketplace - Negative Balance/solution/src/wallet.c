#include "wallet.h"

#include <stdint.h>
#include <stdio.h>

void wallet_init(wallet_t *wallet) {
    if (wallet == NULL) {
        return;
    }

    wallet->balance = 100;
    wallet->transaction_count = 0;
}

bool wallet_try_purchase(wallet_t *wallet, item_t *item, int quantity, int *total_cost) {
    int32_t signed_quantity = (int32_t)quantity;
    int32_t cost = 0;

    if (wallet == NULL || item == NULL || total_cost == NULL) {
        return false;
    }

    cost = (int32_t)(item->price * signed_quantity);

    if (wallet->balance < cost) {
        return false;
    }

    wallet->balance -= cost;
    item->quantity_owned += signed_quantity;
    wallet->transaction_count += 1;

    *total_cost = cost;
    return true;
}

void wallet_print_details(const wallet_t *wallet) {
    if (wallet == NULL) {
        return;
    }

    puts("\nWallet Details:");
    printf("- Current Balance : %ld\n", wallet->balance);
    printf("- Transactions    : %u\n", wallet->transaction_count);
}
