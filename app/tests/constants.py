import dotenv
from singleton import Singleton

dotenv.load_dotenv()


class StaticData(metaclass=Singleton):
    business_name_1 = "business_1"
    business_id_1 = "00000000-0000-0000-0001-000000000000"
    business_domain_1 = "test.ufaas.io"

    business_name_2 = "business_2"
    business_id_2 = "00000000-0000-0000-0002-000000000000"

    user_id_1_1 = (
        "3fd73ffd-1e0a-4096-adbb-b11bf969cf2b"  # "00000001-0000-0000-0001-000000000001"
    )
    user_id_1_2 = (
        "61337f88-71c8-4f8e-b6f3-f39448d0b1a4"  # "00000001-0000-0000-0001-000000000002"
    )
    user_id_2_1 = "00000001-0000-0000-0002-000000000001"
    user_id_2_2 = "00000001-0000-0000-0002-000000000002"
    wallet_id_1_1 = "00000002-0000-0000-0001-000000000001"
    wallet_id_1_2 = "00000002-0000-0000-0001-000000000002"
    wallet_id_1_3 = "00000002-0000-0000-0001-000000000003"
    wallet_id_2_1 = "00000002-0000-0000-0002-000000000001"
    wallet_id_2_2 = "00000002-0000-0000-0002-000000000002"

    app_id = None
    app_secret = None
