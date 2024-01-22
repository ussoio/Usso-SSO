error_messages = {
    "invalid_email": "Invalid email",
    "invalid_password": "password must be at least 8 characters and contain at least one number, one uppercase letter, one lowercase letter, and one special character",
    "already_exists": "User already exists",
    "not_active": "User already exists but is not active",
    "no_user": "User not found",
    "bad_origin": "Origin not found",
    "unauthorized": "Unauthorized",
    "link_expired": "Link expired. Try to get another link.",
    "expired_refresh_token": "Refresh token expired. Try to login again",
    "expired_access_token": "Access token expired. Try to get a new one using the refresh token",
    "invalid_signature": "Invalid signature",
    "website_not_found": "Website not found",
}


class BaseHTTPException(Exception):
    def __init__(self, status_code: int, error: str, message: str = None):
        self.status_code = status_code
        self.error = error
        self.message = message
        if message is None:
            self.message = error_messages[error]
        super().__init__(message)
