from django.urls import path, include
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('auth/register/', view=RegiaterUserView.as_view(), name='signup'),
    path('auth/login/', view=LoginView.as_view(), name="login"),
    path('auth/password-reset/', view=PasswordResetRequestView.as_view(), name="password-reset"),
    path('auth/password-reset-confirm/<uidb64>/<token>/', view=PasswordResetConfirm.as_view(), name="password-reset-confirm"),
    path('auth/set-new-password/<uidb64>/<token>/', view=SetNewPasswordView.as_view(), name="set-new-password"),
    path('auth/verify/', view=VerifyOtpView.as_view(), name='verify'),
    path('auth/user/', view=UserDetailView.as_view(), name="user"),
    path('auth/token/',  CustomObtainPairedView.as_view(), name="token_obtain_pair"),
    path('auth/referesh/', TokenRefreshView.as_view(), name="token_refresh"),

    path('order/', view=CreateOrderView.as_view(), name="orders"),
    path('all-orders/', view=AllOrders.as_view(), name="order"),
    path('drivers/', view=AllDriver.as_view(), name='drivers'),
    path('track-orders/', view=TrackOrder.as_view(), name='track-orders'),
    path('driver-orders/', view=DriverOrders.as_view(), name='driver-orders'),
]