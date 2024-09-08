from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(User)
admin.site.register(OtpTokens)

@admin.register(DeliveryBoy)
class DeliveryBoyAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone_number', 'vehicle_number', 'availability')
    search_fields = ('user__username', 'phone_number', 'vehicle_number')


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'user', 'pickup_address', 'status', 'delivery_date', 'created_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('order_id', 'user__firstname', 'package_details')
    ordering = ('-created_at',)

admin.site.register(Message)