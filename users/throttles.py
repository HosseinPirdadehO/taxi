# from rest_framework.throttling import AnonRateThrottle

# class OTPThrottle(AnonRateThrottle):
#     rate = '5/hour'


# from rest_framework.views import APIView
# from rest_framework.response import Response
# from .throttles import OTPThrottle

# class SendOTPView(APIView):
#     throttle_classes = [OTPThrottle] روش استفاده در api

#     def post(self, request, *args, **kwargs):
#         # منطق ارسال OTP
#         return Response({"detail": "OTP sent"})
