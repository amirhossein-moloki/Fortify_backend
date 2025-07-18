from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from .models import User,Profile
from django.http import Http404
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, ProfileSerializer, LoginSerializer, RegisterSerializer
from django.contrib.auth.forms import PasswordResetForm
from django_ratelimit.decorators import ratelimit
from django.template.loader import render_to_string
import logging
from django.contrib.auth import login
import random
import string
from django.utils import timezone
from datetime import timedelta
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
logger = logging.getLogger(__name__)
from django.utils.encoding import force_bytes
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework import status
from datetime import datetime, timezone, timedelta
from django.utils import timezone
from datetime import timedelta
import string
import random
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.auth import authenticate
from .serializers import LoginSerializer
from django.http import HttpResponse
from .utils import send_activation_email, send_otp_email


class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            Profile.objects.create(user=user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            try:
                send_activation_email(user, token, uid)
            except Exception as e:
                logger.error(f"Error sending email: {e}")
                return Response({"message": "Error sending confirmation email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                "message": "Please confirm your email address to complete the registration.",
                "access_token": access_token
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    try:
                        send_otp_email(user)
                        return Response({
                            "message": "Login successful! Please check your email for the OTP link."
                        }, status=status.HTTP_200_OK)
                    except Exception as e:
                        logger.error(f"Error sending OTP email: {e}")
                        return Response({"message": "Error sending OTP email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response({
                        "message": "Account is not active. Please check your email for activation."
                    }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                "message": "Invalid credentials."
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# ویو تایید ایمیل
class ActivateEmailAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            # دیکد کردن شناسه کاربر
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            # بررسی توکن تأیید
            if default_token_generator.check_token(user, token):
                # فعال کردن کاربر
                user.is_active = True
                user.save()

                # ایجاد توکن‌های جدید برای دسترسی و رفرش
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                # ارسال پاسخ موفقیت و توکن‌ها
                return Response({
                    "message": "Email successfully confirmed!",
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid token or user does not exist."}, status=status.HTTP_400_BAD_REQUEST)

# ویو برای بازیابی رمز عبور
class PasswordResetAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "If an account exists with this email, a password reset link has been sent."}, status=status.HTTP_200_OK)

        # تولید توکن JWT
        refresh = RefreshToken.for_user(user)
        reset_token = str(refresh.access_token)

        # لینک بازنشانی رمز عبور
        reset_link = f'https://fortify-frontend.vercel.app/password-reset/{urlsafe_base64_encode(force_bytes(user.pk))}/{reset_token}/'

        # ارسال ایمیل
        email_subject = 'Password Reset'
        email_message = render_to_string('reset_password_email.html', {
            'reset_link': reset_link,
            'support_email': 'support@yourdomain.com',
            'user_name': user.username,
        })

        send_mail(
            email_subject,
            '',  # محتوای متنی
            'no-reply@yourdomain.com',
            [user.email],
            fail_silently=False,
            html_message=email_message  # محتوای HTML
        )

        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)

# ویو تایید بازیابی رمز عبور
class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            # بررسی توکن JWT
            try:
                AccessToken(token)  # بررسی اعتبار توکن
            except TokenError:
                return Response({"message": "Token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)

            # تنظیم رمز عبور جدید
            new_password = request.data.get('password')
            if new_password:
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Password not provided."}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid user."}, status=status.HTTP_400_BAD_REQUEST)

# ویو برای تغییر رمز عبور
class PasswordChangeAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, uidb64, token):
        password = request.data.get('password')
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))  # تبدیل رشته به force_str
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({"message": "Password changed successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid token or user does not exist."}, status=status.HTTP_400_BAD_REQUEST)


# ویو برای آپدیت پروفایل کاربری با JWT
class UpdateProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        data = request.data

        # آپدیت اطلاعات کاربری
        user_serializer = UserSerializer(user, data=data.get('user', {}), partial=True)

        if user_serializer.is_valid():
            user_serializer.save()
        else:
            return Response({"user_errors": user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        # بررسی وجود پروفایل و ایجاد در صورت نبود
        profile, created = Profile.objects.get_or_create(user=user)

        # آپدیت پروفایل
        profile_serializer = ProfileSerializer(profile, data=data.get('profile', {}), partial=True)

        if profile_serializer.is_valid():
            profile_serializer.save()
            return Response({
                "message": "Profile updated successfully!" + (" Profile was created." if created else ""),
                "user": user_serializer.data,
                "profile": profile_serializer.data
            }, status=status.HTTP_200_OK)
        else:
            return Response({"profile_errors": profile_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)




# ویو برای خروج کاربر
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()  # غیرفعال کردن توکن
            return Response({"message": "Logout successful!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)


# ویو برای حذف حساب کاربری
class DeleteAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully!"}, status=status.HTTP_204_NO_CONTENT)

class OTPVerifyAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, otp):
        try:
            # جستجوی کاربر بر اساس کد OTP
            user = User.objects.get(otp=otp)

            # بررسی زمان انقضای OTP
            if not user.otp_expiration or user.otp_expiration < timezone.now():
                return Response({
                    "message": "OTP expired or invalid. Please request a new one."
                }, status=status.HTTP_400_BAD_REQUEST)

            # بررسی اعتبار OTP
            if user.is_otp_valid():
                # اعتبار سنجی موفق
                # ایجاد توکن JWT
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token

                # پس از ورود، OTP پاک می‌شود
                user.otp = None  # OTP را پاک می‌کنیم
                user.otp_expiration = None  # انقضای OTP را پاک می‌کنیم
                user.save()

                # بازگرداندن توکن‌ها و نام کاربری در پاسخ
                return Response({
                    "message": "Login successful!",
                    "access_token": str(access_token),
                    "refresh_token": str(refresh),
                    "username": user.username  # اضافه کردن نام کاربری به پاسخ
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    "message": "Invalid OTP."
                }, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({
                "message": "User not found or invalid OTP."
            }, status=status.HTTP_400_BAD_REQUEST)




class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]  # نیاز به احراز هویت

    def get(self, request, username, *args, **kwargs):
        try:
            # دریافت کاربر بر اساس نام کاربری
            user = User.objects.get(username=username)

            # دریافت پروفایل کاربر (در صورتی که پروفایل وجود داشته باشد)
            profile = Profile.objects.filter(user=user).first()

            # بررسی مالکیت پروفایل
            is_owner = request.user == user

            # سریالایز کردن داده‌ها
            user_serializer = UserSerializer(user)
            profile_serializer = ProfileSerializer(profile) if profile else None
            user_serializer=UserSerializer(user) if is_owner else None

            # بازگرداندن داده‌های سریالایز شده به همراه وضعیت مالکیت
            return Response({
                'is_owner': is_owner,
                'profile': profile_serializer.data if profile_serializer else None,
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

class SearchUserView(APIView):
    def get(self, request):
        username = request.query_params.get('username', None)
        email = request.query_params.get('email', None)

        # جستجو بر اساس username
        if username:
            try:
                user = User.objects.get(username=username)
                user_serializer = UserSerializer(user)
                return Response(user_serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'detail': 'User not found with this username.'}, status=status.HTTP_404_NOT_FOUND)

        # جستجو بر اساس email
        elif email:
            try:
                user = User.objects.get(email=email)
                user_serializer = UserSerializer(user)
                return Response(user_serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'detail': 'User not found with this email.'}, status=status.HTTP_404_NOT_FOUND)

        # اگر هیچ پارامتر جستجویی مشخص نشده باشد
        return Response({'detail': 'Please provide either a username or an email.'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change password for the authenticated user and refresh JWT token
    """
    user = request.user
    old_password = request.data.get("old_password")
    new_password = request.data.get("new_password")

    # Verify the old password
    if not user.check_password(old_password):
        return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

    # Update the password
    if new_password:
        user.set_password(new_password)
        user.save()

        # Invalidate old tokens by issuing new ones
        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Password changed successfully.",
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }, status=status.HTTP_200_OK)
    else:
        return Response({"error": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)


class ResendActivationEmailAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email, is_active=False)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            send_activation_email(user, token, uid)
            return Response({"message": "Activation email resent successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "No inactive user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error resending activation email: {e}")
            return Response({"message": "Error resending activation email."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendOTPAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        try:
            user = User.objects.get(username=username)
            send_otp_email(user)
            return Response({"message": "New OTP sent successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"message": "No user found with this username."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error resending OTP: {e}")
            return Response({"message": "Error sending new OTP."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshTokenAPIView(APIView):
    """
    This view checks the remaining lifetime of the refresh token.
    If it's close to expiration, it generates a new refresh token along with the access token.
    Otherwise, only a new access token is issued.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response({"message": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Validate the provided refresh token
            refresh = RefreshToken(refresh_token)

            # Check the expiration time of the refresh token
            expiration = datetime.fromtimestamp(refresh['exp'], tz=timezone.utc)
            remaining_time = expiration - datetime.now(timezone.utc)

            # Define threshold for issuing a new refresh token
            threshold = timedelta(hours=1)  # Issue a new refresh token if less than 1 hour remains

            # Generate tokens
            new_access_token = str(refresh.access_token)
            response_data = {"access_token": new_access_token}

            if remaining_time < threshold:
                # If the remaining time is less than the threshold, issue a new refresh token
                new_refresh_token = str(refresh)
                response_data["refresh_token"] = new_refresh_token

            return Response(response_data, status=status.HTTP_200_OK)

        except TokenError:
            return Response({"message": "Invalid or expired refresh token."}, status=status.HTTP_401_UNAUTHORIZED)

