#ifndef SHOP_H
#define SHOP_H

#include <stddef.h>

typedef struct {
    const char *name;
    int price;
    int quantity_owned;
} item_t;

enum {
    ITEM_COFFEE = 0,
    ITEM_BOOK,
    ITEM_LAPTOP,
    ITEM_COUNT
};

void shop_init(item_t items[ITEM_COUNT]);
void shop_print_catalog(const item_t items[ITEM_COUNT]);
void shop_print_inventory(const item_t items[ITEM_COUNT]);
item_t *shop_get_item_by_menu_choice(item_t items[ITEM_COUNT], int menu_choice);

#endif
