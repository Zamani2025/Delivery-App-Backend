from rest_framework import status, viewsets
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.request import Request
from .serializers import *
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import *
from rest_framework.permissions import IsAuthenticated
from .utils import send_code_to_user
import pyotp
import random
import string
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from fcm_django.models import FCMDevice
# from firebase_admin.messaging import Message, Notification
# Create your views here.

class CustomObtainPairedView(TokenObtainPairView):
    serializer_class = CustomObtainPairedSerializer

class UserDetailView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request:Request):
        user = request.user
        serializer = ProfileSerializer(user, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)

class RegiaterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request:Request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            send_code_to_user(email=user['email'])
            data = {
                "data" : serializer.data,
                "message": f"Hi, {user['first_name']} thanks for signing up a passcode"
            }
            return Response(data=data, status=status.HTTP_201_CREATED)
        
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyOtpView(GenericAPIView):
    def post(self, request:Request):
        otp_code = request.data.get('otp')
        try:
            user_code = OtpTokens.objects.get(otp=otp_code)
            user = user_code.user
            if pyotp.TOTP(user_code.secret_key, interval=120, digits=6).verify(otp_code):

                if not user.is_active and not user.is_verified:
                    user.is_active = True
                    user.is_verified = True
                    user.save()
                    data = {
                        "message": "Account email verified successfully!"
                    }
                    return Response(data=data, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Code is invalid user already verified!"}, status=status.HTTP_400_BAD_REQUEST)
                   
            else:
                return Response({"message": "Invalid code, code has expired"}, status=status.HTTP_400_BAD_REQUEST)
            
        except OtpTokens.DoesNotExist:
            return Response({"message": "Passcode not provided"}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request:Request):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request:Request):
        serializer = self.serializer_class(data=request.data, context = {"request": request})
        serializer.is_valid(raise_exception=True)
        return Response({"message": "A link has been sent to your email to reset your password"}, status=status.HTTP_200_OK)

class PasswordResetConfirm(GenericAPIView):
    def get(self, request:Request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                return Response({"message": "token is invalid or has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({"success": True, "message":"Credentials is valid", "uidb64": uidb64, "token": token}, status=status.HTTP_200_OK)
        
        except DjangoUnicodeDecodeError:
            return Response({"message": "token is invalid or has expired"}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request:Request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

class LogoutUserView(GenericAPIView):
    serializer_class = LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request:Request):
        pass

class CreateOrderView(GenericAPIView):
    serializer_class = OrderSerializer
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]

    def post(self, request:Request):
        order_data = request.data
        driver_data = request.data.get('driver_id')
        user = request.user
        driver = DeliveryBoy.objects.get(id=driver_data)
        if not driver.availability:
            return Response({"error": "Driver is not available"}, status=status.HTTP_400_BAD_REQUEST)
        
        driver.availability = False
        customer = User.objects.get(id=user.id)
        characters = string.ascii_uppercase + string.digits
        generated_string = ''.join(random.choices(characters, k=5))
        delivery = Order(
            user=customer,
            driver=driver,
            pickup_address = order_data['pickup_address'],
            delivery_address = order_data['delivery_address'],
            order_id = generated_string,
            package_details = order_data['package_details'],
            receiver_phone = order_data['receiver_phone'],
            receiver_name = order_data['receiver_name'],
            status = 'pending',
        )
        driver.save()
        
        delivery.save()
        return Response({"message": "Delivery created successfully"}, status=status.HTTP_201_CREATED)
    
    def get(self, request:Request):
        user_data = request.user
        order = self.queryset.filter(user=user_data)
        serializer = self.serializer_class(order, many=True)
        data = {
            "data": serializer.data,
            "message": "All orders"
        }
        return Response(data=data, status=status.HTTP_200_OK)


class AllDriver(GenericAPIView):
    queryset = DeliveryBoy.objects.all()
    serializer_class = DeliveryBoySerializer
    permission_classes = [IsAuthenticated]


    def get(self, request:Request):
        drivers = self.queryset.filter(availability=True)

        serializer = self.serializer_class(drivers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AllOrders(GenericAPIView):
    serializer_class = OrderSerializer
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]

    def get(self, request:Request):
        user = request.user
        data = Order.objects.filter(user=user)
        serializer = self.serializer_class(data, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

class CancelOrder(GenericAPIView):
    queryset = Order.objects.all()

    def post(self, request:Request, id):
        order = self.queryset.get(pk=id)
        driver = DeliveryBoy.objects.filter(user=order.driver.user).first()
        if order.status == "pending":
            order.status = "cancelled"
            order.save()
            return Response(data={"message":"Order cancelled successfully"}, status=status.HTTP_200_OK)
        elif order.status == "cancelled":
            driver.availability = True
            driver.save()
            order.delete()
            return Response(data={"message":"Order deleted successfully"}, status=status.HTTP_200_OK)
        elif order.status == "delivered":
            order.delete()
            return Response(data={"message":"Order deleted successfully"}, status=status.HTTP_200_OK)
        
class TrackOrder(GenericAPIView):
    serializer_class = OrderSerializer
    queryset = Order.objects.all()

    def post(self, request:Request):
        order_id = request.data.get('order_id')
        try:
            orders = self.queryset.get(order_id=order_id)
            if orders.status == "accepted":
                return Response({"message": "Order has been accept but not on the way"}, status=status.HTTP_200_OK)
            elif orders.status == "cancelled":
                return Response({"message": "Order with this ID has been cancelled"}, status=status.HTTP_200_OK)
            elif orders.status == "pending":
                return Response({"message": "Order with this ID is still on pending, kindly wait for the driver to accept your order"}, status=status.HTTP_200_OK)
            elif orders.status == "delivered":
                return Response({"message": "Order with this ID has already been delivered"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Order with this ID is on transit"}, status=status.HTTP_200_OK)
        except Order.DoesNotExist:
            return Response({"message": "Order with this ID does'nt exist"}, status=status.HTTP_404_NOT_FOUND)

class DriverOrders(GenericAPIView):
    serializer_class = OrderSerializer
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]

    def get(self, request:Request):
        user = request.user
        delivery_name = DeliveryBoy.objects.get(user=user)
        data = Order.objects.filter(driver=delivery_name)
        serializer = self.serializer_class(data, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)



class ChangeOrderStatus(GenericAPIView):
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]

    
    def post(self, request, order_id):
        user = request.user
        driver = DeliveryBoy.objects.get(user=user)
        order = self.queryset.get(id=order_id)
        if order.status == "pending":
            order.status = "accepted"
            order.save()
            return Response({"message": f"You've started accepted delivery item with the ID of {order.order_id} from {order.user.first_name}"}, status=status.HTTP_200_OK)
        elif order.status == "accepted":
            order.status = "in_transit"
            message = Message.objects.create(
                order=order,
                driver=driver,
                user=order.user,
                message="Your order is on the way now"
            )
            message.save()
            order.save()
            return Response({"message": f"You've started your delivery {order.order_id}"}, status=status.HTTP_200_OK)
        elif order.status == "in_transit": 
            order.status = "delivered"
            order.save()
            return Response({"message": f"You've delivered {order.order_id} to {order.receiver_name}"}, status=status.HTTP_200_OK)
        elif order.status == "delivered":
            driver.availability = True
            driver.save()
            order.delete()
            return Response({"message": f"You've deleted the order successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"message":"Can not change the status of this order"})
        
class RejectOrder(GenericAPIView):
    queryset = Order.objects.all()
    permission_classes = [IsAuthenticated]
        
    def post(self, request:Request, order_id):

        user = request.user
        driver = DeliveryBoy.objects.get(user=user)
        order = self.queryset.get(id=order_id)

        if order.status == "pending":
            order.status = "cancelled"
            message = Message.objects.create(
                order=order,
                driver=driver,
                user=order.user,
                message=f"Your order with the ID of {order.order_id} has been rejected by {driver.user.first_name} {driver.user.last_name}"
            )
            driver.availability = True
            driver.save()
            message.save()
            order.save()
            return Response({"message": "You have successfully rejected the Order"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Can not reject this Order"}, status=status.HTTP_404_NOT_FOUND)
        
class DeleteMessage(GenericAPIView):
    queryset = Message.objects.all()
    permission_classes = [IsAuthenticated]
        
    def post(self, request:Request, message_id):
        message = self.queryset.get(id=message_id)
        message.delete()

        return Response({"message": "Message successfully deleted"}, status=status.HTTP_200_OK)



class AllMessages(GenericAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Message.objects.all()
    serializer_class = MessageSerializer


    def get(self, request:Request):
        user_data = request.user
        try:
            messages = Message.objects.filter(user=user_data).order_by('-id')
            print(messages)
        except Message.DoesNotExist:
            messages = None
        serializers = MessageSerializer(messages, many=True)
        data = {
            "data": serializers.data
        }
        return Response(data=data, status=status.HTTP_200_OK)


class SaveFcmToken(GenericAPIView):

    def post(self, request:Request):
        token = request.POST.get('token')
        user_type = request.POST.get('user_type')

        user = request.user
        user.fcm_token = token
        user.save()

        return Response({'message': "Token saved successfully"}, status=status.HTTP_200_OK)