from apps.models.base import AuthMethod
from apps.models.website import WebsiteConfig
from pydantic import BaseModel


class AnonConfig(BaseModel):
    name: str | None = None
    logo: str | None = None
    udps: set[AuthMethod] = set()
    providers: set[AuthMethod] = set()

    # @classmethod
    def from_config(self, config: WebsiteConfig):
        self.name = config.name
        self.logo = config.logo
        for method in config.available_methods:
            if method.udp:
                self.udps.add(method)
            else:
                self.providers.add(method)

        return self
