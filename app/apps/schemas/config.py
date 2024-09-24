from typing import Literal

from pydantic import BaseModel, StringConstraints
from typing_extensions import Annotated

from apps.models.base import AuthMethod


class ShapeModel(BaseModel):
    borderRadius: int | None = None


class PaletteColorModel(BaseModel):
    main: Annotated[str, StringConstraints(pattern=r"^#(?:[0-9a-fA-F]{3}){1,2}$")]


class PaletteModel(BaseModel):
    primary: PaletteColorModel = PaletteColorModel(main="#dddddd")
    secondary: PaletteColorModel = PaletteColorModel(main="#aaaaaa")
    text: PaletteColorModel = PaletteColorModel(main="#000000")


class TypographyModel(BaseModel):
    fontFamily: str | None = None
    fontSize: int = 14


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


class OptionModel(BaseModel):
    name: str
    api: str
    identifier: str
    placeholder: str
    description: str
    regex: str | None = None
    secrets: list[SecretModel]


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


class ConfigModel(BaseModel):
    branding: BrandingModel
    legal: LegalModel
    methods: list[ProviderModel | CredentialModel]
    captcha_api: str | None = None
    localization: LocalizationModel


def get_config_methods(methods: list[AuthMethod]):
    credentials: dict[str, list[SecretModel]] = {}
    providers: list[AuthMethod] = []
    for i, method in enumerate(methods):
        if method.is_credential:
            key = method.value.split("/")[0]
            credentials.setdefault(key, []).append(method.get_secret_model())
        else:
            providers.append(method)

    regexes = {
        "email": r"^[a-zA-Z\._]+@[a-zA-Z0-9\.-_]+\.[a-zA-Z]{2,}$",
        "user": r"^[a-zA-Z_][a-zA-Z0-9_]{2,16}$",
        "phone": r"^(?:\+?98|0098|0)9[0-9]{9}$",
    }

    credential = CredentialModel(
        options=[
            OptionModel(
                name=key,
                api="/auth/1st-step",
                identifier=key,
                placeholder=key.capitalize(),
                description=f"Enter your {key}",
                regex=regexes[key],
                secrets=[c.model_dump() for c in credentials[key]],
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


def get_config_model(config):
    return ConfigModel(
        branding=config.branding if config.branding else get_branding_model(config),
        legal=config.legal if config.legal else LegalModel(),
        methods=get_config_methods(config.available_methods),
        localization=LocalizationModel(),
    )
