import random
import re
import string

username_regex = re.compile(r"^[a-z]")
national_code_regex = re.compile(r"^\d{10}$")
iran_phone_regex = re.compile(r"^(?:\+?98|0098|0)9\d{9}$")
phone_regex = re.compile(r"^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$")


def is_valid_iran_code(inp):
    if not national_code_regex.search(inp):
        return False

    check = int(inp[9])
    s = sum(int(inp[x]) * (10 - x) for x in range(9)) % 11
    if s >= 2:
        s = 11 - s
    return s == check


def is_valid_iran_mobile(inp):
    return iran_phone_regex.search(inp)


def format_mobile(inp, country_code="98"):
    if inp.startswith("+"):
        inp = inp[1:]
    if inp.startswith("00"):
        inp = inp[2:]
    if inp.startswith("0"):
        inp = inp[1:]
    if len(inp) == 10:
        return str(country_code + inp)
    return str(inp)
    return int(country_code + inp[-10:])


def is_username(username):
    return username_regex.search(username)


def token_generator():
    return random.randrange(10000, 99999)


def __key(key, value):
    return f"{key}{value}"


def token_key(token):
    return __key("TOKENUSER_", token)


def user_key(uid):
    return __key("USERTOKEN_", uid)


def user_buy(code):
    return __key("USERBUY_", code)


def user_temp(user_id, key):
    return f"USERTEMP_{user_id}_{key}"


def generate_random_chars(length=6, characters=string.ascii_letters + string.digits):
    # Generate the random characters
    return "".join(random.choices(characters, k=length))
