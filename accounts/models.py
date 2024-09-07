from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
from rest_framework_simplejwt.tokens import RefreshToken

class User(AbstractBaseUser, PermissionsMixin):
    email = models.CharField(unique=True, max_length=50, verbose_name=_("Email Address"))
    first_name = models.CharField(max_length=20, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=20, verbose_name=_("Last Name"))
    phone = models.CharField(max_length=15, null=True, blank=True)
    address = models.CharField(max_length=20, null=True, blank=True)
    user_type = models.CharField(max_length=30, default="customer")
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateField(auto_now_add=True)
    last_login = models.DateField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }

class OtpTokens(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, unique=True)
    secret_key = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.user.first_name}- {self.otp}"
    
    class Meta:
        verbose_name_plural = "Otp Tokens"
    

class ResetOtpTokens(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, unique=True)
    secret_key = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.user.first_name}- {self.otp}"
    

class DeliveryBoy(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    vehicle_number = models.CharField(max_length=20, blank=True, null=True)
    availability = models.BooleanField(default=False)

    def __str__(self):
        return self.user.first_name
    
    class Meta:
        verbose_name_plural = "Delivery Boy"

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)


    def __str__(self) -> str:
        return self.user.first_name

class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in_transit', 'In Transit'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    driver = models.ForeignKey(DeliveryBoy, on_delete=models.SET_NULL, null=True, blank=True)
    order_id = models.CharField(max_length=100, unique=True)
    delivery_address = models.CharField(max_length=255)
    pickup_address = models.CharField(max_length=255)
    receiver_name = models.CharField(max_length=255, null=True)
    receiver_phone = models.CharField(max_length=255, null=True)
    package_details = models.TextField()
    delivery_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)    
    
    
    
    def __str__(self):
        return f"Order {self.order_id} for {self.user.first_name}"