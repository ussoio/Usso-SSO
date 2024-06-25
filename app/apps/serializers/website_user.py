from apps.models import base
from pydantic import BaseModel


class AuthenticatorDTO(BaseModel):
    auth_method: base.AuthMethod = base.AuthMethod.email_password
    representor: str
