import random
from django.core.mail import EmailMessage
import pyotp
from .models import User, OtpTokens, ResetOtpTokens
from django.conf import settings


def send_code_to_user(email):
    user = User.objects.get(email=email)
    
    secret_key = pyotp.random_base32()
    otp = pyotp.TOTP(secret_key, digits=6, interval=120).now()
    subject = "Activate Your Account"
    message = f"<div style='background-color: #c2c2c2; padding: 15px;'><div style='margin:0; padding: 15px; background: #fff; border-radius: 15px;'><h2>Hi {user.first_name} {user.last_name},</h2> <p>You created an account on yougandev.com, you need to verify your email. Please enter the otp below to verify your email.</p> <p style='text-align:center; background-color: #5865F2; padding: 15px; color: #fff; border-radius: 5px; margin-top: 40px; width: 150px; font-size: 30px; font-weight: bold;'>{otp}</p></div> <div style='text-align:center; margin-top: 20px 0;'><p>&copy; 2024 <a>Blog</a></p></div></div>"
    to_email = email
    from_email = settings.EMAIL_HOST_USER
    email = EmailMessage(subject, message, to=[to_email], from_email=from_email)
    email.content_subtype = 'html'
    email.send(fail_silently=True)
    otp = OtpTokens.objects.create(
        user=user,
        otp=otp,
        secret_key=secret_key,
    )

def send_reset_code_to_user(email):
    user = User.objects.get(email=email)
    
    secret_key = pyotp.random_base32()
    otp = pyotp.TOTP(secret_key, digits=6, interval=120).now()
    subject = "Reset Your Account"
    message = f"<div style='background-color: #c2c2c2; padding: 15px;'><div style='margin:0; padding: 15px; background: #fff; border-radius: 15px;'><h2>Hi {user.first_name} {user.last_name},</h2> <p>You requested to reset your password on yougandev.com. Please enter the otp below to reset your email.</p> <p style='text-align:center; background-color: #5865F2; padding: 15px; color: #fff; border-radius: 5px; margin-top: 40px; width: 150px; font-size: 30px; font-weight: bold;'>{otp}</p></div> <div style='text-align:center; margin-top: 20px 0;'><p>&copy; 2024 <a>Blog</a></p></div></div>"
    to_email = email
    from_email = settings.EMAIL_HOST_USER
    email = EmailMessage(subject, message, to=[to_email], from_email=from_email)
    email.content_subtype = 'html'
    email.send()
    otp = ResetOtpTokens.objects.create(
        user=user,
        otp=otp,
        secret_key=secret_key,
    )

def send_normal_email(data):
    email = EmailMessage(
        subject= data['email_subject'],
        body=data['email_body'],
        from_email= settings.EMAIL_HOST_USER,
        to= data['to_email']
    )
    email.send()