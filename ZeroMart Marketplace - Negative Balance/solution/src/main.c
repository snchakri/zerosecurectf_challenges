#include <stdbool.h>
#include <stdio.h>

#include "flag.h"
#include "input.h"
#include "shop.h"
#include "wallet.h"

#define QTY_MIN (-10000)
#define QTY_MAX (10000)

static void print_main_menu(long balance, const item_t items[ITEM_COUNT]) {
    (void)items;

    puts("\n=== ZeroMart Marketplace ===");
    printf("Balance: %ld ZeroCoins\n\n", balance);
    shop_print_catalog(items);
    puts("4. Check Inventory");
    puts("5. View Wallet Details");
    puts("6. Try to unlock FLAG");
    puts("7. Exit");
}

static void handle_purchase(wallet_t *wallet, item_t *items, int menu_choice) {
    int quantity = 0;
    int total_cost = 0;
    item_t *selected = shop_get_item_by_menu_choice(items, menu_choice);

    if (selected == NULL) {
        puts("Invalid item choice.");
        return;
    }

    printf("\nYou selected: %s (%d coins each)\n", selected->name, selected->price);
    if (!prompt_int_in_range("How many would you like to buy? ", QTY_MIN, QTY_MAX, &quantity)) {
        puts("Invalid quantity. Use an integer in range [-10000, 10000].");
        return;
    }

    puts("Processing transaction...");
    if (!wallet_try_purchase(wallet, selected, quantity, &total_cost)) {
        puts("Transaction denied: insufficient coins.");
        return;
    }

    printf("Cost: %d ZeroCoins\n", total_cost);
    printf("You now have: %ld ZeroCoins\n", wallet->balance);
}

static void handle_flag_attempt(const wallet_t *wallet) {
    long missing = 0;

    if (flag_can_unlock(wallet)) {
        puts("\nFLAG UNLOCKED!");
        puts(flag_value());
        return;
    }

    missing = FLAG_PRICE - wallet->balance;
    printf("\nYou have %ld ZeroCoins. The flag costs %ld ZeroCoins.\n", wallet->balance, FLAG_PRICE);
    printf("You need: %ld more ZeroCoins.\n", missing);
}

int main(void) {
    bool running = true;
    int choice = 0;
    wallet_t wallet;
    item_t items[ITEM_COUNT];

    wallet_init(&wallet);
    shop_init(items);

    puts("Welcome to ZeroMart!");
    puts("Tip: All purchases are final. Finance is weird around here.");

    while (running) {
        print_main_menu(wallet.balance, items);
        if (!prompt_int_in_range("\nChoice: ", 1, 7, &choice)) {
            puts("Invalid menu choice.");
            continue;
        }

        switch (choice) {
            case 1:
            case 2:
            case 3:
                handle_purchase(&wallet, items, choice);
                break;
            case 4:
                shop_print_inventory(items);
                break;
            case 5:
                wallet_print_details(&wallet);
                break;
            case 6:
                handle_flag_attempt(&wallet);
                break;
            case 7:
                running = false;
                break;
            default:
                puts("Invalid menu choice.");
                break;
        }
    }

    puts("Thanks for shopping at ZeroMart.");
    return 0;
}
