error_messages = {
    "invalid_email": "Invalid email",
    "invalid_password": "password must be at least 8 characters and contain at least one number, one uppercase letter, one lowercase letter, and one special character",
    "already_exists": "User already exists",
    "already_exists_wrong_secret": "User already exists, with a different secret",
    "not_active": "User already exists but is not active",
    "no_user": "User not found",
    "bad_origin": "Origin not found",
    "unauthorized": "Unauthorized",
    "link_expired": "Link expired. Try to get another link.",
    "expired_refresh_token": "Refresh token expired. Try to login again",
    "expired_access_token": "Access token expired. Try to get a new one using the refresh token",
    "invalid_signature": "Invalid signature",
    "website_not_found": "Website not found",
    "oath_failed": "Oauth authentication failed",
    "no_email": "No email provided",
    "forbidden": "Forbidden",
    "user_not_found": "Requested user not found",
    "otp_not_found": "OTP not found",
    "credential_exists": "Credential already exists",
}

error_messages_fa = {
    "invalid_email": "ایمیل نامعتبر است",
    "invalid_password": "رمز عبور باید حداقل ۸ کاراکتر باشد و شامل حداقل یک عدد، یک حرف بزرگ، یک حرف کوچک و یک کاراکتر ویژه باشد",
    "already_exists": "کاربر قبلا ثبت شده است",
    "already_exists_wrong_secret": "کاربر قبلا ثبت شده است، یا رمز اشتباه است",
    "not_active": "کاربر قبلا ثبت شده است اما فعال نیست",
    "no_user": "کاربر یافت نشد",
    "bad_origin": "مبدا یافت نشد",
    "unauthorized": "کد وارد شده صحیح نیست",
    "link_expired": "لینک منقضی شده است. لطفا دوباره تلاش کنید",
    "expired_refresh_token": "نشست شما منقضی شده است. لطفا دوباره وارد شوید",
    "expired_access_token": "دسترسی منقضی شده است. لطفا از توکن تازه سازی استفاده کنید",
    "invalid_signature": "امضا نامعتبر است",
    "website_not_found": "وبسایت یافت نشد",
    "oath_failed": "احراز هویت از طریق اوتنتیکیشن ناموفق بود",
    "no_email": "ایمیلی وارد نشده است",
    "forbidden": "دسترسی غیر مجاز",
    "user_not_found": "کاربر درخواستی یافت نشد",
    "otp_not_found": "کد یکبار مصرف یافت نشد",
    "credential_exists": "اعتبارنامه قبلا ثبت شده است",
}


class BaseHTTPException(Exception):
    def __init__(self, status_code: int, error: str, message: str = None, **kwargs):
        self.status_code = status_code
        self.error = error
        self.message = message
        if message is None:
            if kwargs.get("language") == "fa":
                self.message = error_messages_fa.get(error, error)
            else:
                self.message = error_messages.get(error, error)
        super().__init__(message)
