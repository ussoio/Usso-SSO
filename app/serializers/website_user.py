from app.models import base
from pydantic import BaseModel, Field

class AuthenticatorDTO(BaseModel):
    auth_method: base.AuthMethod = base.AuthMethod.email_password
    representor: str
