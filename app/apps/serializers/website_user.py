from pydantic import BaseModel

from apps.models import base


class AuthenticatorDTO(BaseModel):
    auth_method: base.AuthMethod = base.AuthMethod.email_password
    representor: str
