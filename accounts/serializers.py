from rest_framework import serializers
from rest_framework_simplejwt.tokens import Token
from .models import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_str, smart_bytes
from django.urls import reverse
from . utils import send_normal_email
from .tokens import password_token_generator
from rest_framework_simplejwt.tokens import RefreshToken, TokenError



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name']

class DeliveryBoySerializer(serializers.ModelSerializer):
    user = UserSerializer()
    class Meta:
        model = DeliveryBoy
        fields = ['id', 'user','phone_number', 'vehicle_number', 'availability']

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, write_only=True)
    driver_profile = DeliveryBoySerializer(required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'user_type', 'password', 'driver_profile']

    # def validate(self, attrs):
    #     password = attrs.get('password', '')
    #     password2 = attrs.get('password2', '')
        # if password != password2:
        #     raise serializers.ValidationError("passwords do not match")
        # return attrs
    
    def create(self, validated_data):
        user_type = validated_data['user_type']
        driver_data = validated_data.pop('driver_profile', None)
        user = User.objects.create_user(
            email= validated_data['email'],
            user_type= validated_data['user_type'],
            last_name= validated_data['last_name'],
            first_name= validated_data['first_name'],
            password= validated_data['password'],
        )

        if user_type == "driver" and driver_data:
            DeliveryBoy.objects.create(user=user, **driver_data)

        return user
    

    
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=100, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)
    

    class Meta:
        model = User
        fields = ['email', 'full_name', 'password', 'access_token', 'refresh_token']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request=request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("Invalid credentials try again")
        
        if not user.is_active:
            raise AuthenticationFailed("Email is not veirfied")
        
        user_tokens = user.tokens()

        return {
            "email": email,
            "full_name": user.get_full_name,
            "access_token": str(user_tokens.get('access')),
            "refresh_token": str(user_tokens.get('refresh'))
        }
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = password_token_generator.make_token(user)
            request = self.context.get('request')
            site_domain = get_current_site(request=request).domain
            relative_link = reverse('password-reset-confirm', kwargs={"uidb64": uidb64, "token": token})
            abslink = f"http://{site_domain}{relative_link}"
            email_body = f"Hi use the link below to reset your password \n {abslink}"
            data = {
                "email_body": email_body,
                "email_subject": "Reset your Password",
                "to_email": [user.email]
            }
            send_normal_email(data=data)
        return super().validate(attrs)

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64 = serializers.CharField(write_only=True, max_length=255)
    token = serializers.CharField(write_only=True, max_length=255)

    class Meta:
        fields = ['password', 'confirm_password', 'uid64', 'token']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise AuthenticationFailed("Reset link is invalid or has expired", 401)
            
            if password != confirm_password:
                raise AuthenticationFailed("Passwords do not match")
            
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            return AuthenticationFailed("Link is invalid or has expired")

class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs
    
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail("bad_token")

class CustomObtainPairedSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        token['email'] = user.email
        token['user_type'] = user.user_type
        return token
    
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name", "phone", "address", 'user_type']

class OrderSerializer(serializers.ModelSerializer):
    driver_id = serializers.IntegerField(write_only=True, required=True)
    driver = DeliveryBoySerializer()

    class Meta:
        model = Order
        fields = ['id', 'order_id', 'user', 'status', 'driver','receiver_name','receiver_phone', 'driver_id', 'delivery_address', 'pickup_address', 'package_details', 'created_at']

    def create(self, validated_data):
        driver_id = validated_data.pop('driver_id', None)
        order = Order.objects.create(**validated_data)

        if driver_id:
            try:
                driver = DeliveryBoy.objects.get(id=driver_id)
                order.driver = driver
                order.status = 'in_transit'
                order.save()
            except DeliveryBoy.DoesNotExist:
                raise serializers.ValidationError({"driver_id": 'Driver not found'})
            
        return order
    
class MessageSerializer(serializers.ModelSerializer):
    driver = DeliveryBoySerializer()
    order = OrderSerializer()
    model = Message
    fields = ["id", "message", "order", "driver"]