import asyncio
import json
import os

import aiohttp
import dotenv
# from celery import shared_task

from . import singleton

dotenv.load_dotenv()

KAVENEGAR_API_KEY = os.getenv("KAVENEGAR_API_KEY")
INFOBIP_API_KEY = os.getenv("INFOBIP_API_KEY")


async def send_kavenegar_async(phone: str, text: str):
    kavenegar = f"https://api.kavenegar.com/v1/{KAVENEGAR_API_KEY}/sms/send.json"
    params = {
        "receptor": phone,
        "message": text,
        "sender": "100088008088",
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(kavenegar, params=params) as response:
            return await response.json()


async def send_infobip_async(phone: str, text: str):
    base_url = "ppepv3.api.infobip.com"
    send_url = f"https://{base_url}/sms/2/text/advanced"

    payload = json.dumps(
        {
            "messages": [
                {"destinations": [{"to": phone}], "from": "InfoSMS", "text": text}
            ]
        }
    )

    headers = {
        "Authorization": f"App {INFOBIP_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(send_url, data=payload, headers=headers) as response:
            data = await response.text()
            print(data)


async def send_sms_async(phone: str, text: str):
    if str(phone).startswith("98"):
        return await send_kavenegar_async(phone, text)
    return await send_infobip_async(phone, text)


def send_message(phone: str, text: str):
    asyncio.run(send_sms_async(phone, text))


# @shared_task
def send_message_task(phone: str, text: str):
    send_message(phone, text)


class Kavenegar(metaclass=singleton.Singleton):
    me = "kavenegar"
    bot_type = "kavenegar"

    def __init__(self) -> None:
        pass

    def send_message(self, phone: str, text: str):
        send_message_task.delay(phone, text)
