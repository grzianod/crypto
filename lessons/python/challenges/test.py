from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

key = b"1234567890abcdefabcdef1234567890"
output_cookie = b""

def sanitize_field(field: str):
    return field \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")


def parse_cookie(cookie: str) -> dict:
    parsed = {}
    for field in cookie.split("&"):
        key, value = field.strip().split("=")
        key = sanitize_field(key.strip())
        value = sanitize_field(value.strip())
        parsed[key] = value

    return parsed


def login():

    cipher = AES.new(key, AES.MODE_ECB)
    username = "0000000" + pad(b'true', AES.block_size).decode() + "000000000"
    cookie = "username=" + username + "&admin=false"
    print(cookie)
    output_cookie = cipher.encrypt(pad(cookie.encode(), AES.block_size)).hex().encode()
    print(output_cookie)

    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    tampered = output_cookie[0:32] + output_cookie[96:128] + output_cookie[64:96] + output_cookie[32:64]
    print(output_cookie)
    dec_cookie = unpad(cipher.decrypt(tampered), AES.block_size).decode()
    print(dec_cookie)
    token = parse_cookie(dec_cookie)

    if token["admin"] != 'true':
        print("You are not an admin!")
        return

    print(f"OK! Your flag.")

def get_flag():

    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    tampered = output_cookie[0:32] + output_cookie[96:128] + output_cookie[64:96] + output_cookie[32:64]
    print(output_cookie)
    dec_cookie = unpad(cipher.decrypt(tampered), AES.block_size).decode()
    print(dec_cookie)
    token = parse_cookie(dec_cookie)

    if token["admin"] != 'true':
        print("You are not an admin!")
        return

    print(f"OK! Your flag.")


if __name__ == "__main__":
    login()

    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            get_flag()
