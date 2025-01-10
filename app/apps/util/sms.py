import asyncio
import json
import os

import dotenv
import httpx
import requests
import singleton

# from celery import shared_task


dotenv.load_dotenv()

KAVENEGAR_API_KEY = os.getenv("KAVENEGAR_API_KEY")
INFOBIP_API_KEY = os.getenv("INFOBIP_API_KEY")


async def send_kavenegar_template_async(
    phone: str, template: str, token: str, api_key: str = KAVENEGAR_API_KEY
):
    kavenegar = f"https://api.kavenegar.com/v1/{api_key}/verify/lookup.json"
    params = {"receptor": phone, "token": token, "template": template}
    async with httpx.AsyncClient() as client:
        response = await client.get(kavenegar, params=params)
        response.raise_for_status()
        return response.json()


async def send_kavenegar_async(phone: str, text: str, **kwargs):
    kavenegar_api_key = (
        kwargs.get("kavenegar_api_key", KAVENEGAR_API_KEY) or KAVENEGAR_API_KEY
    )
    kavenegar_template = kwargs.get("kavenegar_template", None)

    if kavenegar_template:
        return await send_kavenegar_template_async(
            phone, kavenegar_template, text, kavenegar_api_key
        )
    kavenegar = f"https://api.kavenegar.com/v1/{kavenegar_api_key}/sms/send.json"
    params = {"receptor": phone, "message": text, "sender": "100088008088"}

    async with httpx.AsyncClient() as client:
        response = await client.get(kavenegar, params=params)
        response.raise_for_status()
        return await response.json()


async def send_infobip_async(phone: str, text: str, **kwargs):
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

    async with httpx.AsyncClient() as client:
        response = await client.post(send_url, data=payload, headers=headers)
        data = response.text
        print(data)


async def send_sms_async(phone: str, text: str, **kwargs):
    if str(phone).startswith("98"):
        return await send_kavenegar_async(phone, text, **kwargs)
    return await send_infobip_async(phone, text, **kwargs)


def send_message(phone: str, text: str, **kwargs):
    asyncio.run(send_sms_async(phone, text, **kwargs))


def send_message_task(phone: str, text: str, **kwargs):
    send_message(phone, text, **kwargs)


class Kavenegar(metaclass=singleton.Singleton):
    me = "kavenegar"
    bot_type = "kavenegar"

    def __init__(self) -> None:
        pass

    def send_message(self, phone: str, text: str):
        send_message_task(phone, text)


# Default requests timeout in seconds.
DEFAULT_TIMEOUT = 10


class APIException(Exception):
    pass


class HTTPException(Exception):
    pass


class KavenegarAPI(object):
    """
    https://kavenegar.com/rest.html
    """

    version = "v1"
    host = "api.kavenegar.com"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "charset": "utf-8",
    }

    def __init__(self, apikey, timeout=None, proxies=None):
        """
        :param str apikey: Kavengera API Key
        :param int timeout: request timeout, default is 10
        :param dict proxies: Dictionary mapping protocol to the URL of the proxy:
            {
                'http': 'http://192.168.1.10:3128',
                'https': 'http://192.168.1.10:3129',
            }
        """
        self.apikey = apikey
        self.apikey_mask = f"{apikey[:2]}********{apikey[-2:]}"
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.proxies = proxies

    def __repr__(self):
        return "kavenegar.KavenegarAPI({!r})".format(self.apikey_mask)

    def __str__(self):
        return "kavenegar.KavenegarAPI({!s})".format(self.apikey_mask)

    def _pars_params_to_json(self, params):
        """
        Kavenegar bug, the api server expects the parameters in a JSON-like array format,
        but the requests library form-encode each key-value pair

        Params (dict):
        { sender: ["30002626", "30002627", "30002727", ], }

        request behavior:
        sender=30002626&sender=30002627&sender=30002727

        Server expectation:
        sender=["30002626","30002627","30002727"]
        """
        # Convert lists to JSON-like strings
        formatted_params = {}
        for key, value in params.items():
            if isinstance(value, (dict, list, tuple)):
                formatted_params[key] = json.dumps(value)
            else:
                formatted_params[key] = value
        return formatted_params

    def _request(self, action, method, params=None):
        if params is None:
            params = {}
        if isinstance(params, dict):
            params = self._pars_params_to_json(params)
        url = "https://{}/{}/{}/{}/{}.json".format(
            self.host, self.version, self.apikey, action, method
        )
        try:
            content = requests.post(
                url,
                headers=self.headers,
                auth=None,
                data=params,
                timeout=self.timeout,
                proxies=self.proxies,
            ).content
            try:
                response = json.loads(content.decode("utf-8"))
                if response["return"]["status"] == 200:
                    return response["entries"]
                else:
                    raise APIException(
                        "APIException[{}] {}".format(
                            response["return"]["status"], response["return"]["message"]
                        )
                    )
            except ValueError as e:
                raise HTTPException(e)
        except requests.exceptions.RequestException as e:
            message = str(e).replace(self.apikey, self.apikey_mask)
            raise HTTPException(message) from None

    def sms_send(self, params=None):
        return self._request("sms", "send", params)

    def sms_sendarray(self, params=None):
        return self._request("sms", "sendarray", params)

    def sms_status(self, params=None):
        return self._request("sms", "status", params)

    def sms_statuslocalmessageid(self, params=None):
        return self._request("sms", "statuslocalmessageid", params)

    def sms_select(self, params=None):
        return self._request("sms", "select", params)

    def sms_selectoutbox(self, params=None):
        return self._request("sms", "selectoutbox", params)

    def sms_latestoutbox(self, params=None):
        return self._request("sms", "latestoutbox", params)

    def sms_countoutbox(self, params=None):
        return self._request("sms", "countoutbox", params)

    def sms_cancel(self, params=None):
        return self._request("sms", "cancel", params)

    def sms_receive(self, params=None):
        return self._request("sms", "receive", params)

    def sms_countinbox(self, params=None):
        return self._request("sms", "countinbox", params)

    def sms_countpostalcode(self, params=None):
        return self._request("sms", "countpostalcode", params)

    def sms_sendbypostalcode(self, params=None):
        return self._request("sms", "sendbypostalcode", params)

    def verify_lookup(self, params=None):
        return self._request("verify", "lookup", params)

    def call_maketts(self, params=None):
        return self._request("call", "maketts", params)

    def call_status(self, params=None):
        return self._request("call", "status", params)

    def account_info(self):
        return self._request("account", "info")

    def account_config(self, params=None):
        return self._request("account", "config", params)
