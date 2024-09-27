from typing import Literal

from apps.models.base import AuthMethod
from pydantic import BaseModel, StringConstraints
from typing_extensions import Annotated


class ShapeModel(BaseModel):
    borderRadius: int | None = None


class PaletteColorModel(BaseModel):
    main: Annotated[str, StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$")]
    # light: (
    #     Annotated[str, StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$")] | None
    # ) = None
    # dark: (
    #     Annotated[str, StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$")] | None
    # ) = None
    # contrastText: (
    #     Annotated[str, StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$")] | None
    # ) = None


class PaletteModel(BaseModel):
    primary: PaletteColorModel = PaletteColorModel(main="#dddddd")
    secondary: PaletteColorModel = PaletteColorModel(main="#aaaaaa")


class TypographyModel(BaseModel):
    fontFamily: str | None = None
    fontSize: int = 14
    allVariants: dict[str, str] = {}


class BrandingModel(BaseModel):
    logo: str | None = None
    favicon: str | None = None
    title: str | None = None
    description: str | None = None
    shape: ShapeModel | None = None
    palette: PaletteModel = PaletteModel()
    typography: TypographyModel | None = None


class LegalModel(BaseModel):
    privacy: str = "https://usso.io/fa/privacy/"
    terms: str = "https://usso.io/en/privacy/"


class SecretModel(BaseModel):
    method: str
    name: str
    api: str
    type: str
    placeholder: str
    description: str
    regex: str | None = None
    error: str = "نا معتبر"
    length: int | None = None


class OptionModel(BaseModel):
    name: str
    api: str
    identifier: str
    placeholder: str
    description: str
    regex: str | None = None
    error: str = "نا معتبر"
    secrets: list[SecretModel]
    success: str = "با موفقیت وارد شدید"


class ProviderModel(BaseModel):
    type: Literal["provider"] = "provider"
    text: str
    icon: str
    color: str | None = None
    url: str


class CredentialModel(BaseModel):
    type: Literal["credential"] = "credential"
    options: list[OptionModel]


class LocalizationModel(BaseModel):
    languages: list[Literal["en", "fa"]] = ["fa"]
    default: Literal["en", "fa"] = "fa"
    direction: Literal["ltr", "rtl"] = "rtl"


class ConfigModel(BaseModel):
    branding: BrandingModel
    legal: LegalModel
    methods: list[ProviderModel | CredentialModel]
    captcha_api: str | None = None
    localization: LocalizationModel


def get_config_methods(
    methods: list[AuthMethod], language: str = "fa"
) -> list[ProviderModel | CredentialModel]:
    credentials: dict[str, list[SecretModel]] = {}
    providers: list[AuthMethod] = []
    for i, method in enumerate(methods):
        if method.is_credential:
            key = method.value.split("/")[0]
            credentials.setdefault(key, []).append(method.get_secret_model(language))
        else:
            providers.append(method)

    regexes = {
        "email": r"^[a-zA-Z\._]+@[a-zA-Z0-9\.-_]+\.[a-zA-Z]{2,}$",
        "user": r"^[a-zA-Z_][a-zA-Z0-9_]{2,16}$",
        "phone": r"^(?:\+?98|0098|0)9[0-9]{9}$",
    }

    if language == "fa":
        placeholders = {
            "email": "ایمیل",
            "user": "نام کاربری",
            "phone": "شماره تلفن",
        }
    else:
        placeholders = {
            "email": "Email",
            "user": "Username",
            "phone": "Phone Number",
        }

    credential = CredentialModel(
        options=[
            OptionModel(
                name=key,
                api="/auth/1st-step",
                identifier=key,
                placeholder=placeholders[key],
                description=f"{placeholders[key]} خود را وارد کنید",
                regex=regexes[key],
                secrets=[c.model_dump() for c in credentials[key]],
                error=f"{placeholders[key]} نا معتبر است",
            )
            for key in credentials
        ]
    )
    result = [credential] + [
        ProviderModel(
            text=provider.text,
            icon=provider.icon,
            color=provider.color,
            url=provider.auth_url,
        )
        for provider in providers
    ]

    return result


def get_branding_model(config):
    return BrandingModel(
        title=config.name,
        description=f"به {config.name} خوش آمدید",
        logo=config.logo,
        favicon=config.logo,
        # palette=PaletteModel(
        #     primary=PaletteColorModel(main=config.primary_color),
        #     secondary=PaletteColorModel(main=config.secondary_color),
        #     text=PaletteColorModel(main=config.text_color),
        # ),
        typography=TypographyModel(fontFamily="Vazir, Arial, sans-serif"),
    )


def get_config_model(config, language: str = "fa"):
    return ConfigModel(
        branding=config.branding if config.branding else get_branding_model(config),
        legal=config.legal if config.legal else LegalModel(),
        methods=get_config_methods(config.available_methods, language),
        localization=LocalizationModel(),
    )
