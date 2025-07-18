import random
import string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from datetime import timedelta
from .models import User

def generate_otp(length=6):
    """Generates a random OTP."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def send_otp_email(user):
    """Generates and sends an OTP to the user's email."""
    otp = generate_otp()
    user.otp = otp
    user.otp_expiration = timezone.now() + timedelta(minutes=10)
    user.save()

    otp_link = f'https://fortify-frontend.vercel.app/otp/otp={otp}'
    email_subject = 'Login Attempt - OTP Verification'
    email_message = render_to_string('otp_email.html', {
        'otp': otp,
        'user_name': user.username,
        'otp_link': otp_link,
        'support_email': 'support@yourdomain.com',
    })

    send_mail(
        email_subject,
        '',
        'no-reply@yourdomain.com',
        [user.email],
        fail_silently=False,
        html_message=email_message
    )

def send_activation_email(user, token, uid):
    """Sends an activation email to the user."""
    verification_link = f'https://fortify-frontend.vercel.app/activate-email?uid={uid}&token={token}&email={user.email}'
    login_action_url = 'https://fortify-frontend.vercel.app/login'
    forgot_password_url = 'https://fortify-frontend.vercel.app/forgot-password'
    email_subject = 'Welcome to Fortify - Confirm Your Email'

    email_message = render_to_string('activation_email.html', {
        'verification_link': verification_link,
        'support_email': 'support@example.com',
        'user_name': user.username,
        'login_action_url': login_action_url,
        'forgot_password_url': forgot_password_url,
        'user_email': user.email
    })

    send_mail(
        email_subject,
        '',
        'no-reply@fortify.com',
        [user.email],
        fail_silently=False,
        html_message=email_message
    )
