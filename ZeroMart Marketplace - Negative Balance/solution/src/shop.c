#include "shop.h"

#include <stdio.h>

void shop_init(item_t items[ITEM_COUNT]) {
    items[ITEM_COFFEE].name = "Coffee";
    items[ITEM_COFFEE].price = 10;
    items[ITEM_COFFEE].quantity_owned = 0;

    items[ITEM_BOOK].name = "Book";
    items[ITEM_BOOK].price = 50;
    items[ITEM_BOOK].quantity_owned = 0;

    items[ITEM_LAPTOP].name = "Laptop";
    items[ITEM_LAPTOP].price = 1000;
    items[ITEM_LAPTOP].quantity_owned = 0;
}

void shop_print_catalog(const item_t items[ITEM_COUNT]) {
    puts("ITEMS:");
    printf("1. %-12s (%d coins)\n", items[ITEM_COFFEE].name, items[ITEM_COFFEE].price);
    printf("2. %-12s (%d coins)\n", items[ITEM_BOOK].name, items[ITEM_BOOK].price);
    printf("3. %-12s (%d coins)\n", items[ITEM_LAPTOP].name, items[ITEM_LAPTOP].price);
}

void shop_print_inventory(const item_t items[ITEM_COUNT]) {
    puts("\nYour Inventory:");
    for (size_t i = 0; i < ITEM_COUNT; ++i) {
        printf("- %-12s : %d\n", items[i].name, items[i].quantity_owned);
    }
}

item_t *shop_get_item_by_menu_choice(item_t items[ITEM_COUNT], int menu_choice) {
    switch (menu_choice) {
        case 1:
            return &items[ITEM_COFFEE];
        case 2:
            return &items[ITEM_BOOK];
        case 3:
            return &items[ITEM_LAPTOP];
        default:
            return NULL;
    }
}
