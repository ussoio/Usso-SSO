import asyncio
import base64
import datetime
import json
import os
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
            return base64.b64encode(obj).decode("utf-8")
        if hasattr(obj, "to_json"):
            return obj.to_json()
        return super().default(obj)


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
