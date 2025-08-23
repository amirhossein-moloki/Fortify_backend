# Fortify-backend

This is the backend for the Fortify secure chat application. It's built with Django and Django Rest Framework and features end-to-end encryption for all conversations.

## Features

- User authentication (signup, login, logout)
- User authentication (signup, login, logout)
- End-to-end encrypted real-time chat with Django Channels
- Contact management (add, remove, accept/reject friend requests)
- Real-time notifications
- Secure key exchange using Diffie-Hellman

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/fortify-backend.git
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up the environment variables. Create a `.env` file in the root directory and add the following:
   ```
   DJANGO_SECRET_KEY=your-secret-key
   DEBUG=True
   ALLOWED_HOSTS=localhost,127.0.0.1
   DATABASE_URL=your-database-url
   REDIS_URL=your-redis-url
   EMAIL_HOST=your-email-host
   EMAIL_PORT=your-email-port
   EMAIL_USE_SSL=True
   EMAIL_USE_TLS=False
   EMAIL_HOST_USER=your-email-host-user
   EMAIL_HOST_PASSWORD=your-email-host-password
   ```
5. Run the migrations:
   ```bash
   python manage.py migrate
   ```
6. Run the development server:
   ```bash
   python manage.py runserver
   ```

## Running the tests

To run the tests, run the following command:
```bash
python manage.py test
```
