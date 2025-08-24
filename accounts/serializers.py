from rest_framework import serializers
from .models import User, Profile
from django.core.exceptions import ValidationError

from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(max_length=None, use_url=True, allow_null=True, required=False)
    banner_image = serializers.ImageField(source='profile.banner_image', max_length=None, use_url=True, allow_null=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_online', 'last_seen', 'profile_picture', 'bio', 'banner_image']


class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    social_links = serializers.JSONField(required=False)

    class Meta:
        model = Profile
        fields = [
            'id', 'user', 'date_of_birth', 'gender', 'location', 'website',
            'status_message', 'banner_image', 'social_links'
        ]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm']

    def validate_username(self, value):
        """Check if the username already exists"""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_email(self, value):
        """Check if the email already exists"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already taken.")
        return value

    def validate(self, data):
        """Check if the password and confirm password match"""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords must match."})
        return data

    def create(self, validated_data):
        """Create a new user and hash the password"""
        password = validated_data.pop('password')
        validated_data.pop('password_confirm', None)  # Remove password_confirm field

        user = User(**validated_data)
        user.set_password(password)  # Hash the password before saving
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)
