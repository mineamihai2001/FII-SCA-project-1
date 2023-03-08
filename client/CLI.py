import json


def main_menu():
    print("####### SUPERMARKET #######\n")
    while True:
        print("        1.Begin shop\n")
        menu_choice = input()
        if menu_choice not in "1":
            print("Please select a valid choice between 1 and 2!")
        else:
            break
    if menu_choice == "1":
        return "shop"
    # elif menu_choice == "2":
    #    return "exit"


def cart_menu(user_cart):
    print("\n##### YOUR CART #####")
    total = 0 # sum of all prices in cart
    for i in range(len(user_cart)):
        product_name = user_cart[i]['name']
        product_price = user_cart[i]['price']
        print("{}.{} ... {}"
              .format(str(i+1), product_name, product_price))
        total += float(product_price)
    print("-----TOTAL-----")
    print(str(total),  "\n")
    print("(back)   (submit)")
    # get user input
    while True:
        button = input()
        if button == "back":
            return "ignore"
        elif button == "submit":
            return str(total)
        else:
            print("Invalid input - 'back' or 'submit' required")


def products_menu(items):
    cart = []
    while True:
        print("\n##### Available items #####")
        print("! Enter the number of the item "
              " you wish to add to the cart or exit/cart !")
        shop_items = json.loads(items)
        count = 0
        for item in shop_items['items']:
            count += 1
            print("{}.{} ... {} RON"
                  .format(str(count), item['name'], item['price']))
        
        # get user input
        while True:
            user_input = input()
            if user_input.isnumeric():
                # if a number is provided, check if it corresponds 
                # to a valid product and add product to cart
                number = int(user_input)
                if 1 <= number <= count:
                    cart.append(shop_items['items'][number - 1])
                    break
                else:
                    print("Invalid input - choose a valid product number")
            elif user_input == "cart":
                action = cart_menu(cart)
                if action != "ignore":
                    # a purchase submission
                    return action
                break
            elif user_input == "exit":
                return "exit"
            else:
                print("Invalid input - 'cart', 'exit'" 
                      "or a product number required")
