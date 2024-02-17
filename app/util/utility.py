import asyncio
import base64
import binascii
import datetime
import json
import random
import string
import threading
from functools import wraps

import aiohttp


def generate_random_chars(length=6, characters=string.ascii_letters + string.digits):
    # Generate the random characters
    return "".join(random.choices(characters, k=length))


class JSONSerializer(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(obj, bytes):
            return f'b64:{base64.b64encode(obj).decode("utf-8")}'
        if hasattr(obj, "to_json"):
            return obj.to_json()
        return super().default(obj)


def json_deserializer(dct):
    for key, value in dct.items():
        if isinstance(value, str):
            # Try to decode datetime strings
            try:
                dct[key] = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

            if value.startswith("b64:"):
                base64_str = value[4:]  # Remove the 'b64:' prefix
                try:
                    dct[key] = base64.b64decode(base64_str)
                except (ValueError, TypeError):
                    pass

    return dct


def run_async_in_thread(func):
    """
    Decorator to run an asynchronous function in a separate thread.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = None

        # Function to execute the async function in a new event loop
        def run_async():
            nonlocal result
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(func(*args, **kwargs))
            loop.close()

        # Running the async function in a separate thread
        thread = threading.Thread(target=run_async)
        thread.start()
        thread.join()

        return result

    return wrapper

def fill_template(template: dict | list | str, data: dict):
    if isinstance(template, dict):
        # For dictionaries, recursively apply fill_template to each value
        return {k: fill_template(v, data) for k, v in template.items()}
    elif isinstance(template, list):
        # For lists, recursively apply fill_template to each item
        return [fill_template(item, data) for item in template]
    elif isinstance(template, str):
        # For strings, format using the data dictionary
        try:
            return template.format(**data)
        except KeyError as e:
            # If a key in the template string is not found in the user dict, return the original string
            # Alternatively, you can handle this case differently based on your requirements
            return template
    else:
        # For any other type, return it as is
        return template
