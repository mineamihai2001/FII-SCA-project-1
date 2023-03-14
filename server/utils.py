import json

def get_shop_items():
    with open('inventory.json') as inventory_data:
        items = json.load(inventory_data)
    return items