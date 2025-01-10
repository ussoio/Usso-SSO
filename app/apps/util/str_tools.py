import random
import re
import unicodedata
from functools import lru_cache

username_regex = re.compile(r"^[a-z]")
national_code_regex = re.compile(r"^\d{10}$")
iran_phone_regex = re.compile(r"^(?:\+?98|0098|0)9\d{9}$")
phone_regex = re.compile(
    r"^[\+]?(0{0,2})(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*(\d{1,2})$"
)


def convert_to_english_digits(input_str: str):
    result = []
    for char in input_str:
        if char.isdigit():
            # Convert any unicode digit to its corresponding ASCII digit
            result.append(unicodedata.digit(char))
        else:
            result.append(char)
    return "".join(map(str, result))


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


def email_validator(email: str):
    v = email.lower()
    if v.endswith("@gmail.com"):
        email_user = v.split("@")[0]
        if "+" in email_user:
            email_user = email_user.split("+")[0]
        # email_user = email_user.replace(".", "")
        v = f"{email_user}@gmail.com"

    return v


@lru_cache(maxsize=1024)
def is_valid_mobile(inp):
    return phone_regex.search(inp) or iran_phone_regex.search(inp)


def format_mobile(inp, country_code="98"):
    assert is_valid_mobile(inp)
    inp = "".join(re.findall(r"\d+", inp))

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
