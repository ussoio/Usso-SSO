import asyncio
import logging


def get_all_subclasses(cls: type):
    subclasses = cls.__subclasses__()
    return subclasses + [
        sub for subclass in subclasses for sub in get_all_subclasses(subclass)
    ]


def try_except_wrapper(func):
    if asyncio.iscoroutinefunction(func):

        async def wrapped_func(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logging.error(f"An error occurred in {func.__name__}: {e}")
                return None

    else:

        async def wrapped_func(*args, **kwargs):
            try:
                return await asyncio.to_thread(func, *args, **kwargs)
            except Exception as e:
                logging.error(f"An error occurred in {func.__name__}: {e}")
                return None

    return wrapped_func
