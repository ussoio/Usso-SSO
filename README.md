# Usso-SSO
Usso is a secure and flexible Single Sign-On (SSO) solution for businesses, enabling efficient authentication flows within microservice architectures. With support for multiple authentication methods and robust security features, Usso simplifies user authentication and data management.

## Features
- Secure JWT Authentication: Uses RSA encryption for enhanced security.
- Multiple Authentication Methods: Supports Google, email/password, phone/OTP, and more.
- Custom Subdomain Integration: Easily integrate with your own subdomain.
- Comprehensive Configuration: Manage OTP, email, and token settings.
- API Access: Fetch user data securely using API keys or JWT tokens.

## Usage
### Adding a New Business
1. Create a new business entity with domain and configuration settings.
2. Set up secrets, including RSA keys and OAuth details if needed.
### User Registration and Authentication
1. Register users using supported methods (email/password, Google, etc.).
2. Authenticate users and issue JWT tokens.
3. Manage user sessions and activity logs.
### API Endpoints
- Authentication: Endpoints for user registration, login, and token management.
- User Management: Endpoints for fetching and updating user data.
- Configuration: Endpoints for managing business configuration and secrets.

## Contributing
We welcome contributions! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.

## License
This project is licensed under the Apache 2.0 License. See the [LICENSE](https://github.com/ussoio/Usso-SSO?tab=Apache-2.0-1-ov-file) file for details.

## Contact
For any questions or suggestions, please open an issue or contact us at support@usso.io.