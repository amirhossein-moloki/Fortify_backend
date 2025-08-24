from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from django.utils.encoding import force_str
from .models import User,Profile
from django.http import Http404
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, ProfileSerializer, LoginSerializer, RegisterSerializer
from django.contrib.auth.forms import PasswordResetForm
from django_ratelimit.decorators import ratelimit
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
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
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            try:
                send_activation_email(user, token, uid)
            except Exception as e:
                logger.error(f"Error sending email: {e}")
                return Response({"message": "Error sending confirmation email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({
                "message": "Please confirm your email address to complete the registration."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"message": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"message": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            return Response({
                "message": "Account is not active. Please check your email for activation."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            send_otp_email(user)
            return Response({
                "message": "Login successful! Please check your email for the OTP link."
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error sending OTP email: {e}")
            return Response({"message": "Error sending OTP email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




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
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class PasswordResetAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Don't reveal whether the user exists or not
            return Response({"message": "If an account exists with this email, a password reset link has been sent."}, status=status.HTTP_200_OK)

        # Generate a secure, single-use token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # لینک بازنشانی رمز عبور
        reset_link = f"{settings.FRONTEND_URL}/password-reset-confirm/{uid}/{token}/"

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
            html_message=email_message
        )

        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)


# ویو تایید بازیابی رمز عبور
class PasswordResetConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid user link."}, status=status.HTTP_400_BAD_REQUEST)

        # Check the token
        if not default_token_generator.check_token(user, token):
            return Response({"message": "Token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password
        new_password = request.data.get('password')
        if not new_password:
            return Response({"message": "Password not provided."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)


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

@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class OTPVerifyAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        if not otp:
            return Response({"message": "OTP not provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # جستجوی کاربر بر اساس کد OTP
            user = User.objects.get(otp=otp)

            # بررسی زمان انقضای OTP
            if not user.is_otp_valid():
                return Response({
                    "message": "OTP expired or invalid. Please request a new one."
                }, status=status.HTTP_400_BAD_REQUEST)

            # اعتبار سنجی موفق
            # ایجاد توکن JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            # پس از ورود، OTP پاک می‌شود
            user.otp = None
            user.otp_expiration = None
            user.save()

            # بازگرداندن توکن‌ها و نام کاربری در پاسخ
            return Response({
                "message": "Login successful!",
                "access_token": str(access_token),
                "refresh_token": str(refresh),
                "username": user.username
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                "message": "Invalid OTP."
            }, status=status.HTTP_400_BAD_REQUEST)




class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise Http404

    def get(self, request, username, *args, **kwargs):
        user = self.get_object(username)
        profile, _ = Profile.objects.get_or_create(user=user)

        is_owner = request.user == user

        # Combine user and profile data
        response_data = {
            'is_owner': is_owner,
            'username': user.username,
            'email': user.email,
            'profile_picture': user.profile_picture.url if user.profile_picture else None,
            'bio': user.bio,
            'is_online': user.is_online,
            'last_seen': user.last_seen,
            'date_of_birth': profile.date_of_birth,
            'gender': profile.gender,
            'location': profile.location,
            'website': profile.website,
            'status_message': profile.status_message,
            'banner_image': profile.banner_image.url if profile.banner_image else None,
            'social_links': profile.social_links,
        }
        return Response(response_data, status=status.HTTP_200_OK)

    def patch(self, request, username, *args, **kwargs):
        user = self.get_object(username)
        if request.user != user:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        profile, _ = Profile.objects.get_or_create(user=user)

        # Separate data for User and Profile models
        user_data = {}
        if 'bio' in request.data:
            user_data['bio'] = request.data['bio']
        if 'profile_picture' in request.data:
            user_data['profile_picture'] = request.data['profile_picture']

        profile_data = {}
        profile_fields = ['date_of_birth', 'gender', 'location', 'website', 'status_message', 'social_links']
        for field in profile_fields:
            if field in request.data:
                profile_data[field] = request.data[field]

        if 'banner_image' in request.data:
            profile_data['banner_image'] = request.data['banner_image']

        user_serializer = UserSerializer(user, data=user_data, partial=True)
        profile_serializer = ProfileSerializer(profile, data=profile_data, partial=True)

        user_valid = user_serializer.is_valid()
        profile_valid = profile_serializer.is_valid()

        if user_valid and profile_valid:
            user_serializer.save()
            profile_serializer.save()
            return Response(self.get(request, username).data) # Return the updated profile

        errors = {}
        if not user_valid:
            errors.update(user_serializer.errors)
        if not profile_valid:
            errors.update(profile_serializer.errors)

        return Response(errors, status=status.HTTP_400_BAD_REQUEST)

class SearchUserView(APIView):
    permission_classes = [IsAuthenticated]

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



@ratelimit(key='ip', rate='5/m', block=True)
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


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
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


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
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

