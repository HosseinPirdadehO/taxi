from users.serializers import UserSerializer
from users.models import User
from rest_framework import status
from django.http import Http404
from rest_framework.exceptions import NotFound
from users.serializers import StudentProfileSerializer, DriverProfileSerializer, ParentProfileSerializer
from rest_framework import generics, permissions, status
from users.models import StudentProfile, DriverProfile, ParentProfile
from users.serializers import ParentProfileSerializer
from datetime import timedelta
import hashlib
import random

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404

from rest_framework import generics, permissions, serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from users.mixins import StandardResponseMixin
from users.models import (
    User, PhoneOTP, Referral,
    DriverProfile, ParentProfile, StudentProfile, SchoolProfile,
    TransportAdminProfile, EducationAdminProfile, SuperAdminProfile,
    RoleTypes, Location
)
from users.serializers import (
    SendOTPSerializer, OTPVerifySerializer, TokenResponseSerializer,
    ChangePhoneRequestSerializer, ChangePhoneVerifySerializer,
    ResendOTPSerializer, SetPasswordSerializer, PasswordResetSerializer,
    ReferralMineSerializer, ReferralInviterSerializer,
    FullUserProfileSerializer, CompleteProfileSerializer, UserSerializer,
    SchoolAdminProfileSerializer, DriverProfileSerializer, StudentProfileSerializer,
    UserRegisterWithReferralSerializer, LocationSerializer, OverviewReportSerializer,
    RoleCountSerializer,
    ReferralReportSerializer,
    ActiveUserSerializer,
    NewUserSerializer,
    LocationStatsSerializer,
    PhoneCheckSerializer
)
from rest_framework.permissions import IsAdminUser
from django.db.models import Count, Sum
import logging
logger = logging.getLogger(__name__)

# logger.debug("جزئیات دیباگ")
# logger.info("اتفاق عادی")
# logger.warning("هشدار")
# logger.error("خطا")
# logger.critical("خطای بحرانی")

PROFILE_MODEL_MAP = {
    'driver': DriverProfile,
    'parent': ParentProfile,
    'student': StudentProfile,
    'schooladmin': SchoolProfile,
    'transportadmin': TransportAdminProfile,
    'educationadmin': EducationAdminProfile,
    'superadmin': SuperAdminProfile,
}


class CheckPhoneNumberView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PhoneCheckSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_number = serializer.validated_data['phone_number']

        is_registered = User.objects.filter(phone_number=phone_number).exists()
        message = " این شماره قبلاً ثبت‌نام کرده است." if is_registered else " این شماره جدید است و هنوز ثبت‌نام نشده."

        return Response({
            "success": True,
            "message": message,
            "data": {
                "is_registered": is_registered
            }
        }, status=status.HTTP_200_OK)


class SendOTPView(StandardResponseMixin, generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = SendOTPSerializer

    @swagger_auto_schema(
        request_body=SendOTPSerializer,
        responses={200: openapi.Response('کد تأیید ارسال شد')}
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data['phone_number']
        raw_code = str(random.randint(1000, 9999))

        # 🧹 پاک کردن OTPهای قبلی این شماره
        PhoneOTP.objects.filter(phone_number=phone).delete()

        # 📥 ساخت OTP جدید
        otp_obj = PhoneOTP.objects.create(
            phone_number=phone,
            purpose='registration'
        )
        otp_obj.set_code(raw_code)

        # TODO: ارسال SMS واقعی
        print(f"OTP for {phone} is {raw_code}")

        return self.standard_response(
            success=True,
            message="کد تأیید ارسال شد.",
            data={"otp": raw_code}  # فقط برای محیط توسعه
        )


class VerifyOTPView(StandardResponseMixin, generics.GenericAPIView):
    serializer_class = OTPVerifySerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=OTPVerifySerializer,
        responses={
            200: openapi.Response('ورود یا ثبت‌نام موفق', TokenResponseSerializer),
            400: 'کد تأیید اشتباه یا منقضی شده',
            403: 'محدودیت دسترسی',
        }
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data['phone_number']
        otp = serializer.validated_data['otp']
        referral_code = serializer.validated_data.get('referral_code')
        purpose = serializer.validated_data.get('purpose', 'registration')

        otp_queryset = PhoneOTP.objects.filter(
            phone_number=phone, is_verified=False, purpose=purpose
        )

        try:
            otp_obj = otp_queryset.latest('created_at')
        except PhoneOTP.DoesNotExist:
            return self.error_response(message="کد تأیید معتبر نیست.")

        valid, msg = otp_obj.verify_code(otp)
        if not valid:
            return self.error_response(message=msg)

        if purpose == "change_phone":
            return self._handle_change_phone(request, phone)

        user, created = User.objects.get_or_create(phone_number=phone)
        if created:
            self._initialize_new_user(user, phone, referral_code)

        tokens = self._generate_tokens_for_user(user)
        profile_complete = all([user.first_name, user.last_name])

        response_data = {
            'access': tokens['access'],
            'refresh': tokens['refresh'],
            'profile_complete': profile_complete,
            'is_first_login': created,
        }

        token_serializer = TokenResponseSerializer(data=response_data)
        token_serializer.is_valid(raise_exception=True)

        return self.success_response(
            message="ورود یا ثبت‌نام با موفقیت انجام شد.",
            data=token_serializer.data,
            user=user
        )

    def _handle_change_phone(self, request, phone):
        if not request.user.is_authenticated:
            return self.error_response(
                "برای تغییر شماره ابتدا وارد شوید.", status.HTTP_403_FORBIDDEN)

        if User.objects.filter(phone_number=phone).exclude(id=request.user.id).exists():
            return self.error_response(
                "این شماره قبلاً توسط کاربر دیگری استفاده شده است.", status.HTTP_400_BAD_REQUEST)

        request.user.phone_number = phone
        request.user.is_phone_verified = True
        request.user.save()

        return self.success_response(
            message="شماره تلفن با موفقیت تغییر یافت.",
            user=request.user
        )

    def _initialize_new_user(self, user, phone, referral_code):
        user.is_active = True
        user.is_phone_verified = True

        special_phones = getattr(settings, 'SPECIAL_ADMIN_PHONES', [])
        if phone in special_phones:
            user.system_role = User.SystemRole.SUPERADMIN
            user.is_staff = True
            user.is_superuser = True
        else:
            user.role = User.RoleTypes.USER

        if referral_code:
            inviter = User.objects.filter(referral_code=referral_code).first()
            if inviter:
                Referral.objects.create(
                    inviter=inviter,
                    invited=user,
                    referral_code_used=referral_code
                )
        user.save()

    def _generate_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }


class LogoutView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={'refresh': openapi.Schema(type=openapi.TYPE_STRING)},
        ),
        responses={
            205: 'خروج موفق',
            400: 'توکن نامعتبر یا ارسال نشده'
        }
    )
    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return self.error_response("Refresh token is required.", status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return self.success_response("با موفقیت خارج شدید.", status_code=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return self.error_response("توکن نامعتبر است.", status.HTTP_400_BAD_REQUEST)


class ChangePhoneRequestView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=ChangePhoneRequestSerializer,
        responses={
            200: 'کد تایید به شماره جدید ارسال شد.',
            400: 'شماره موبایل قبلا ثبت شده'
        }
    )
    def post(self, request):
        serializer = ChangePhoneRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_phone = serializer.validated_data['new_phone_number']

        if User.objects.filter(phone_number=new_phone).exists():
            return self.error_response("این شماره قبلا ثبت شده است.", status.HTTP_400_BAD_REQUEST)

        otp = str(random.randint(1000, 9999))
        hashed_code = hashlib.sha256(otp.encode()).hexdigest()

        PhoneOTP.objects.create(
            phone_number=new_phone,
            code=hashed_code,
            purpose='change_phone',
            is_verified=False,
            created_at=timezone.now(),
            failed_attempts=0
        )

        # TODO: ارسال پیامک واقعی به new_phone با otp
        print(f" OTP for changing phone {new_phone} is {otp}")

        return self.success_response("کد تایید به شماره جدید ارسال شد.")


class ChangePhoneVerifyView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=ChangePhoneVerifySerializer,
        responses={
            200: 'شماره موبایل با موفقیت تغییر یافت.',
            400: 'کد تایید اشتباه',
            404: 'کد تأیید یافت نشد'
        }
    )
    def post(self, request):
        serializer = ChangePhoneVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_phone = serializer.validated_data['new_phone_number']
        otp = serializer.validated_data['otp']

        try:
            phone_otp = PhoneOTP.objects.filter(
                phone_number=new_phone, purpose='change_phone', is_verified=False).latest('created_at')
        except PhoneOTP.DoesNotExist:
            return self.error_response("کد تایید یافت نشد.", status.HTTP_404_NOT_FOUND)

        valid, message = phone_otp.verify_code(otp)
        if not valid:
            return self.error_response(message, status.HTTP_400_BAD_REQUEST)

        user = request.user
        user.phone_number = new_phone
        user.is_phone_verified = True
        user.save()

        phone_otp.is_verified = True
        phone_otp.save(update_fields=['is_verified'])

        return self.success_response("شماره موبایل با موفقیت تغییر یافت.")


class ResendOTPView(StandardResponseMixin, APIView):
    permission_classes = [permissions.AllowAny]

    RESEND_OTP_INTERVAL_SECONDS = 60

    @swagger_auto_schema(
        request_body=ResendOTPSerializer,
        responses={
            200: 'کد تأیید مجدداً ارسال شد.',
            429: 'تعداد درخواست‌های زیاد است'
        }
    )
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phone_number']

        last_otp = PhoneOTP.objects.filter(
            phone_number=phone_number).order_by('-created_at').first()

        if last_otp:
            elapsed = timezone.now() - last_otp.created_at
            if elapsed.total_seconds() < self.RESEND_OTP_INTERVAL_SECONDS:
                wait_time = self.RESEND_OTP_INTERVAL_SECONDS - \
                    int(elapsed.total_seconds())
                return self.error_response(
                    f"لطفا {wait_time} ثانیه دیگر تلاش کنید.",
                    status.HTTP_429_TOO_MANY_REQUESTS
                )

        new_code = f"{random.randint(100000, 999999)}"
        hashed_code = hashlib.sha256(new_code.encode()).hexdigest()

        PhoneOTP.objects.create(
            phone_number=phone_number,
            code=hashed_code,
            is_verified=False,
            created_at=timezone.now(),
            failed_attempts=0,
            purpose='resend_otp'
        )

        # TODO: ارسال SMS واقعی به شماره با new_code
        print(f" Resend OTP for {phone_number} is {new_code}")

        return self.success_response("کد تأیید مجدداً ارسال شد.")


class SetPasswordView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=SetPasswordSerializer,
        responses={
            200: 'رمز عبور با موفقیت ذخیره شد.',
            400: 'خطا در داده‌های ارسالی'
        }
    )
    def post(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data['password'])
        user.save()

        return self.success_response("رمز عبور با موفقیت ذخیره شد.")


class PasswordResetView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        request_body=PasswordResetSerializer,
        responses={
            200: 'رمز عبور با موفقیت تغییر کرد.',
            400: 'کد تأیید اشتباه یا منقضی شده',
            404: 'کاربر یافت نشد',
            403: 'تعداد تلاش‌های ناموفق بیش از حد'
        }
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data['phone_number']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']

        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return self.error_response("کاربری با این شماره یافت نشد.", status.HTTP_404_NOT_FOUND)

        otp_qs = PhoneOTP.objects.filter(
            phone_number=phone_number,
            is_verified=False,
            purpose='password_reset'
        ).order_by('-created_at')

        if not otp_qs.exists():
            return self.error_response("کد تأیید معتبر یافت نشد.", status.HTTP_400_BAD_REQUEST)

        otp_obj = otp_qs.first()

        if timezone.now() > otp_obj.created_at + timedelta(minutes=2):
            return self.error_response("کد تأیید منقضی شده است.", status.HTTP_400_BAD_REQUEST)

        hashed_input = hashlib.sha256(otp.encode()).hexdigest()
        if hashed_input != otp_obj.code:
            otp_obj.failed_attempts += 1
            otp_obj.save(update_fields=['failed_attempts'])
            if otp_obj.failed_attempts >= 5:
                return self.error_response("تعداد تلاش‌های ناموفق بیش از حد مجاز است.", status.HTTP_403_FORBIDDEN)
            return self.error_response("کد تأیید اشتباه است.", status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        otp_obj.is_verified = True
        otp_obj.save(update_fields=['is_verified'])

        return self.success_response("رمز عبور با موفقیت تغییر کرد.")


class RegisterUserWithReferralView(StandardResponseMixin, generics.CreateAPIView):
    serializer_class = UserRegisterWithReferralSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="ثبت‌نام کاربر با کد معرف",
        operation_description="ثبت‌نام کاربر جدید همراه با ثبت کد معرف (Referral Code) در صورت وجود.",
        request_body=UserRegisterWithReferralSerializer,
        responses={201: openapi.Response(
            description="ثبت‌نام موفق",
            examples={
                "application/json": {
                    "success": True,
                    "message": "ثبت‌نام با موفقیت انجام شد.",
                    "data": {
                        "user_id": 42,
                        "phone_number": "09121234567"
                    }
                }
            }
        )}
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.success_response(
            message="ثبت‌نام با موفقیت انجام شد.",
            data={
                "user_id": user.id,
                "phone_number": user.phone_number
            }
        )


class MyReferralsView(StandardResponseMixin, generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReferralMineSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['created_at']
    search_fields = ['invited_user__phone_number']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    @swagger_auto_schema(
        operation_summary="لیست کاربران دعوت‌شده توسط من",
        operation_description="کاربرانی که توسط این کاربر دعوت شده‌اند (رفرال‌های من).",
        responses={200: ReferralMineSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        logger.debug(
            f"کاربر {request.user.id} درخواست لیست رفرال‌های خود را ارسال کرد.")
        response = super().get(request, *args, **kwargs)
        logger.debug(f"تعداد رفرال‌های بازگردانده شده: {len(response.data)}")
        return response

    def get_queryset(self):
        user = self.request.user
        logger.debug(f"ایجاد کوئریست برای کاربر با شناسه {user.id}")
        qs = Referral.objects.filter(inviter=user)
        logger.debug(f"تعداد رفرال‌ها در کوئری: {qs.count()}")
        return qs


class MyInviterView(StandardResponseMixin, generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReferralInviterSerializer
    # filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    # filterset_fields = ['status', 'created_at']
    # search_fields = ['invited_user__phone_number']
    # ordering_fields = ['created_at']
    # ordering = ['-created_at']

    @swagger_auto_schema(
        operation_summary="مشاهده دعوت‌کننده من",
        operation_description="نمایش اطلاعات کاربری که این کاربر را دعوت کرده است.",
        responses={
            200: openapi.Response(
                description="دعوت‌کننده یافت شد",
                schema=ReferralInviterSerializer
            ),
            404: "کاربر دعوت‌کننده‌ای ندارد."
        }
    )
    def get(self, request, *args, **kwargs):
        inviter = self.get_object()
        if inviter is None:
            return self.error_response(message="شما توسط هیچ کاربری دعوت نشده‌اید.", status_code=404)
        serializer = self.get_serializer(inviter)
        return self.success_response(data=serializer.data)

    def get_object(self):
        referral = getattr(self.request.user, "received_referral", None)
        return referral.inviter if referral else None


class ReferralStatsView(StandardResponseMixin, generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="آمار رفرال‌های من",
        operation_description="نمایش تعداد و آخرین تاریخ دعوت‌هایی که انجام داده‌ام.",
        responses={200: openapi.Response(
            description="آمار دعوت‌ها",
            examples={
                "application/json": {
                    "success": True,
                    "message": "آمار دعوت‌ها",
                    "data": {
                        "count": 5,
                        "last_invited_at": "2025-07-18T16:32:00.000Z"
                    }
                }
            }
        )}
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        referrals = Referral.objects.filter(inviter=user)
        count = referrals.count()
        last = referrals.order_by(
            '-created_at').first().created_at if referrals.exists() else None

        data = {
            'count': count,
            'last_invited_at': last,
        }

        return self.success_response(
            data=data,
            message=_("آمار دعوت‌ها")
        )


class CompleteProfileView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="دریافت اطلاعات کامل پروفایل",
        operation_description="این متد اطلاعات کامل پروفایل کاربر لاگین‌شده را بازمی‌گرداند.",
        responses={200: openapi.Response(
            description="اطلاعات پروفایل کاربر",
            schema=CompleteProfileSerializer
        )}
    )
    def get(self, request):
        user = request.user
        serializer = CompleteProfileSerializer(user)
        return self.standard_response(
            success=True,
            message="اطلاعات پروفایل کامل دریافت شد.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        operation_summary="تکمیل یا بروزرسانی کامل پروفایل",
        operation_description="تمام فیلدهای پروفایل باید ارسال شوند. اگر فیلدی ارسال نشود، مقدار قبلی پاک می‌شود.",
        request_body=CompleteProfileSerializer,
        responses={200: openapi.Response(
            description="پروفایل با موفقیت بروزرسانی شد.",
            schema=CompleteProfileSerializer
        )}
    )
    def put(self, request):
        user = request.user
        serializer = CompleteProfileSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.standard_response(
                success=True,
                message="پروفایل با موفقیت بروزرسانی شد.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
        return self.standard_response(
            success=False,
            message="خطا در داده‌های ورودی.",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )

    @swagger_auto_schema(
        operation_summary="بروزرسانی جزئی پروفایل",
        operation_description="فقط فیلدهایی که نیاز به تغییر دارند ارسال می‌شوند. فیلدهای دیگر تغییری نمی‌کنند.",
        request_body=CompleteProfileSerializer,
        responses={200: openapi.Response(
            description="پروفایل با موفقیت بروزرسانی شد.",
            schema=CompleteProfileSerializer
        )}
    )
    def patch(self, request):
        user = request.user
        serializer = CompleteProfileSerializer(
            user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.standard_response(
                success=True,
                message="پروفایل با موفقیت بروزرسانی شد.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
        return self.standard_response(
            success=False,
            message="خطا در داده‌های ورودی.",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    فقط ادمین‌ها اجازه ویرایش دارند، بقیه فقط خواندن.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_staff or request.user.is_superuser


class UserRetrieveUpdateView(StandardResponseMixin, generics.RetrieveUpdateAPIView):
    """
    مشاهده و ویرایش کاربر با شناسه مشخص.
    """

    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]

    serializer_class = FullUserProfileSerializer

    def get_serializer_class(self):

        if self.request.method in ['PUT', 'PATCH']:
            return CompleteProfileSerializer
        return FullUserProfileSerializer

    @swagger_auto_schema(
        operation_summary="دریافت جزئیات کاربر با شناسه",
        responses={
            200: FullUserProfileSerializer,
            404: 'کاربر یافت نشد',
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="بروزرسانی کامل اطلاعات کاربر",
        request_body=CompleteProfileSerializer,
        responses={
            200: CompleteProfileSerializer,
            400: 'خطا در داده‌های ارسالی',
            403: 'عدم دسترسی',
            404: 'کاربر یافت نشد',
        }
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="بروزرسانی جزئی اطلاعات کاربر",
        request_body=CompleteProfileSerializer,
        responses={
            200: CompleteProfileSerializer,
            400: 'خطا در داده‌های ارسالی',
            403: 'عدم دسترسی',
            404: 'کاربر یافت نشد',
        }
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Override to return standard response format"""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return self.standard_response(
            success=True,
            message="جزئیات کاربر دریافت شد.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    def update(self, request, *args, **kwargs):
        """Override to handle partial/full update with standard response"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.standard_response(
            success=True,
            message="کاربر با موفقیت بروزرسانی شد.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )


logger = logging.getLogger(__name__)


class UserMeView(StandardResponseMixin, generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return FullUserProfileSerializer
        return CompleteProfileSerializer

    @swagger_auto_schema(
        operation_summary="دریافت پروفایل خود کاربر",
        responses={200: FullUserProfileSerializer()}
    )
    def get(self, request, *args, **kwargs):
        logger.info(f"User {request.user.id} requested profile.")
        response = super().get(request, *args, **kwargs)

        # اضافه کردن داده‌های اضافی به پاسخ
        profile_complete = self._is_profile_complete(request.user)
        role_display = dict(RoleTypes.choices).get(
            request.user.role, request.user.role)

        data_with_extra = {
            "user": response.data,
            "profileComplete": profile_complete,
            "isPhoneVerified": request.user.is_phone_verified,
            "roleDisplay": role_display,
        }

        return self.standard_response(
            success=True,
            message="پروفایل کاربر دریافت شد.",
            data=data_with_extra,
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        operation_summary="ویرایش پروفایل خود کاربر (کامل یا جزئی)",
        request_body=CompleteProfileSerializer,
        responses={
            200: CompleteProfileSerializer(),
            400: "خطا در داده‌های ورودی",
        }
    )
    def put(self, request, *args, **kwargs):
        return self._update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل خود کاربر",
        request_body=CompleteProfileSerializer,
        responses={
            200: CompleteProfileSerializer(),
            400: "خطا در داده‌های ورودی",
        }
    )
    def patch(self, request, *args, **kwargs):
        return self._update(request, *args, **kwargs, partial=True)

    def _update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = CompleteProfileSerializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.standard_response(
            success=True,
            message="پروفایل با موفقیت بروزرسانی شد.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    def _is_profile_complete(self, user):
        required_fields = [
            user.first_name,
            user.last_name,
            user.national_code,
            user.province,
            user.city,
        ]
        return all(required_fields)


class TestTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "message": "توکن معتبر است.",
            "user_phone": user.phone_number,
            "user_id": str(user.id),
            "user_full_name": user.get_full_name(),
        })


# ---- ----


class UserListView(StandardResponseMixin, generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['role', 'is_active',
                        'date_joined', 'first_name', 'last_name']
    search_fields = ['phone_number',
                     'national_code', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'first_name', 'last_name']
    ordering = ['-date_joined']

    @swagger_auto_schema(
        operation_summary="دریافت لیست کاربران",
        operation_description="این endpoint لیستی از کاربران را با امکان فیلتر، جستجو و مرتب‌سازی برمی‌گرداند.",
        responses={
            200: openapi.Response(
                description="لیست کاربران",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'count': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'results': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_OBJECT))
                            }
                        )
                    }
                )
            )
        }
    )
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return self.standard_response(
            success=True,
            message=_("لیست کاربران با موفقیت دریافت شد."),
            data={
                "count": self.paginator.page.paginator.count if self.paginator and hasattr(self, 'paginator') else len(response.data),
                "results": response.data
            },
            status_code=status.HTTP_200_OK
        )


class SchoolListView(generics.ListAPIView):
    queryset = SchoolProfile.objects.all()
    serializer_class = SchoolAdminProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    filterset_fields = ['school_type', 'school_location', 'school_name']
    search_fields = ['school_name',
                     'school_location__title', 'school_location__address']
    ordering_fields = ['school_name']
    ordering = ['school_name']

    @swagger_auto_schema(operation_summary="دریافت لیست مدارس")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class DriverListView(generics.ListAPIView):
    queryset = DriverProfile.objects.all()
    serializer_class = DriverProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    # در مدل DriverProfile فیلدهای: car_type و is_verified وجود دارد
    filterset_fields = ['car_type', 'is_verified']

    # جستجو در شماره موبایل، شماره گواهینامه و نام راننده (از طریق user FK)
    search_fields = ['user__phone_number', 'license_number',
                     'user__first_name', 'user__last_name']

    ordering_fields = ['license_number', 'user__first_name']
    ordering = ['user__first_name']

    @swagger_auto_schema(operation_summary="دریافت لیست رانندگان")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class StudentListView(generics.ListAPIView):
    queryset = StudentProfile.objects.all()
    serializer_class = StudentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    # فیلتر بر اساس پایه، وضعیت فعال و id لوکیشن مدرسه (FK)
    filterset_fields = ['grade', 'is_active', 'school_location']

    # جستجو در شماره موبایل، نام و نام خانوادگی، کد مدرسه، نام کلاس
    search_fields = ['user__phone_number', 'user__first_name',
                     'user__last_name', 'school_id_code', 'class_name']

    ordering_fields = ['grade', 'user__first_name', 'class_name']
    ordering = ['user__first_name']

    @swagger_auto_schema(operation_summary="دریافت لیست دانش‌آموزان")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class TransportAdminListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(role=RoleTypes.TRANSPORT_ADMIN, is_active=True)

    @swagger_auto_schema(operation_summary="دریافت لیست ادمین‌های ترابری")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class EducationAdminListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(role=RoleTypes.EDUCATION_ADMIN, is_active=True)

    @swagger_auto_schema(operation_summary="دریافت لیست ادمین‌های آموزشی")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class SuperAdminListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(role=RoleTypes.SUPER_ADMIN, is_active=True)

    @swagger_auto_schema(operation_summary="دریافت لیست سوپرادمین‌ها")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ParentListView(generics.ListAPIView):
    queryset = ParentProfile.objects.select_related(
        'user').filter(user__role=RoleTypes.PARENT)
    serializer_class = ParentProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    # جستجو در نام، نام خانوادگی و شماره موبایل والد
    search_fields = ['user__first_name',
                     'user__last_name', 'user__phone_number']

    ordering_fields = ['user__first_name', 'user__date_joined']
    ordering = ['-user__date_joined']

    @swagger_auto_schema(operation_summary="دریافت لیست والدین")
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

# -----------------------


class IsOwnerProfile(permissions.BasePermission):
    """
    اجازه می‌دهد فقط صاحب پروفایل بتواند دسترسی داشته باشد.
    """

    def has_object_permission(self, request, view, obj):
        # فرض بر این است که هر پروفایل یک فیلد user دارد که FK به User است
        return obj.user == request.user


# ---------- دانش‌آموز -----------

class StudentRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsOwnerProfile]
    serializer_class = StudentProfileSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        return StudentProfile.objects.all()

    @swagger_auto_schema(
        operation_summary="دریافت پروفایل دانش‌آموز با شناسه",
        responses={200: StudentProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل دانش‌آموز با شناسه",
        responses={200: StudentProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل دانش‌آموز با شناسه",
        responses={200: StudentProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


class CurrentStudentProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = StudentProfileSerializer

    @swagger_auto_schema(
        operation_summary="دریافت یا ویرایش پروفایل دانش‌آموز فعلی",
        responses={200: StudentProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        try:
            profile = StudentProfile.objects.get(user=self.request.user)
        except StudentProfile.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("پروفایل دانش‌آموز یافت نشد.")
        self.check_object_permissions(self.request, profile)
        return profile

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل دانش‌آموز فعلی",
        responses={200: StudentProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل دانش‌آموز فعلی",
        responses={200: StudentProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


# ---------- راننده -----------

class DriverRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsOwnerProfile]
    serializer_class = DriverProfileSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        return DriverProfile.objects.all()

    @swagger_auto_schema(
        operation_summary="دریافت پروفایل راننده با شناسه",
        responses={200: DriverProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل راننده با شناسه",
        responses={200: DriverProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل راننده با شناسه",
        responses={200: DriverProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


class CurrentDriverProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = DriverProfileSerializer

    @swagger_auto_schema(
        operation_summary="دریافت یا ویرایش پروفایل راننده فعلی",
        responses={200: DriverProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        try:
            profile = DriverProfile.objects.get(user=self.request.user)
        except DriverProfile.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("پروفایل راننده یافت نشد.")
        self.check_object_permissions(self.request, profile)
        return profile

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل راننده فعلی",
        responses={200: DriverProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل راننده فعلی",
        responses={200: DriverProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


# ---------- والد -----------

class ParentRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated, IsOwnerProfile]
    serializer_class = ParentProfileSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        return ParentProfile.objects.all()

    @swagger_auto_schema(
        operation_summary="دریافت پروفایل والد با شناسه",
        responses={200: ParentProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل والد با شناسه",
        responses={200: ParentProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل والد با شناسه",
        responses={200: ParentProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


class CurrentParentProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ParentProfileSerializer

    @swagger_auto_schema(
        operation_summary="دریافت یا ویرایش پروفایل والد فعلی",
        responses={200: ParentProfileSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        try:
            profile = ParentProfile.objects.get(user=self.request.user)
        except ParentProfile.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("پروفایل والد یافت نشد.")
        self.check_object_permissions(self.request, profile)
        return profile

    @swagger_auto_schema(
        operation_summary="ویرایش کامل پروفایل والد فعلی",
        responses={200: ParentProfileSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی پروفایل والد فعلی",
        responses={200: ParentProfileSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)
# ---- -----

# Location


class LocationListCreateView(generics.ListCreateAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="لیست مکان‌ها",
        responses={200: LocationSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ایجاد مکان جدید",
        request_body=LocationSerializer,
        responses={201: LocationSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class LocationRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="مشاهده جزئیات مکان",
        responses={200: LocationSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش کامل مکان",
        request_body=LocationSerializer,
        responses={200: LocationSerializer}
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="ویرایش جزئی مکان",
        request_body=LocationSerializer,
        responses={200: LocationSerializer}
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_summary="حذف مکان",
        responses={204: "Deleted"}
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class CurrentUserLocationView(generics.RetrieveAPIView):
    serializer_class = LocationSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="دریافت مکان کاربر فعلی",
        responses={200: LocationSerializer, 404: 'Not Found'}
    )
    def get(self, request, *args, **kwargs):
        logger.debug(f"کاربر {request.user.id} درخواست مکان خود را ارسال کرد.")
        return super().get(request, *args, **kwargs)

    def get_object(self):
        user = self.request.user
        location = None

        if user.role == RoleTypes.STUDENT:
            profile = getattr(user, 'studentprofile', None)
            if profile:
                location = profile.home_location or profile.school_location

        elif user.role == RoleTypes.PARENT:
            parent_profile = getattr(user, 'parentprofile', None)
            if parent_profile:
                locations = []
                for student_profile in parent_profile.students.all():
                    if student_profile.home_location:
                        locations.append(student_profile.home_location)
                    elif student_profile.school_location:
                        locations.append(student_profile.school_location)
                if locations:
                    location = locations[0]

        elif user.role == RoleTypes.SCHOOL_ADMIN:
            profile = getattr(user, 'schoolprofile', None)
            if profile:
                location = profile.school_location

        elif user.role == RoleTypes.DRIVER:
            profile = getattr(user, 'driverprofile', None)
            # اگر خواستیم لوکیشن راننده را اضافه کنید، اینجا قرار
            location = None

        elif user.role == RoleTypes.EDUCATION_ADMIN:
            profile = getattr(user, 'educationadminprofile', None)
            # location = profile.region_location if profile else None
            location = None

        elif user.role == RoleTypes.TRANSPORT_ADMIN:
            profile = getattr(user, 'transportadminprofile', None)
            # location = profile.region_location if profile else None
            location = None

        elif user.role == RoleTypes.SUPER_ADMIN:
            profile = getattr(user, 'superadminprofile', None)
            location = None

        if location is None:
            logger.warning(
                f"لوکیشن برای کاربر {user.id} با نقش {user.role} یافت نشد.")
            raise Http404("مکان برای کاربر پیدا نشد.")

        return location

# -----------------
# -----------------
# ----------------

# تاریخچه‌ و آمارکلی


class OverviewReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="آمار کلی کاربران",
        responses={200: OverviewReportSerializer}
    )
    def get(self, request):
        total_users = User.objects.count()
        total_referrals = Referral.objects.count()
        active_users_today = User.objects.filter(
            last_login__date=timezone.now().date()).count()

        data = {
            "total_users": total_users,
            "total_referrals": total_referrals,
            "active_users_today": active_users_today
        }
        return Response(OverviewReportSerializer(data).data)


class RoleCountReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="تعداد کاربران به تفکیک نقش",
        responses={200: RoleCountSerializer(many=True)}
    )
    def get(self, request):
        role_counts = User.objects.values("role").annotate(count=Count("id"))
        return Response([RoleCountSerializer(role).data for role in role_counts])


class ReferralReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="آمار دعوت کاربران",
        responses={200: ReferralReportSerializer(many=True)}
    )
    def get(self, request):
        stats = Referral.objects.values("inviter__phone_number").annotate(
            invited_count=Count("invited"))
        result = [
            {"inviter_name": item["inviter__phone_number"],
             "invited_count": item["invited_count"]}
            for item in stats
        ]
        return Response([ReferralReportSerializer(r).data for r in result])


class ActiveUsersReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="کاربران فعال ۷ روز اخیر",
        responses={200: ActiveUserSerializer(many=True)}
    )
    def get(self, request):
        since = timezone.now() - timedelta(days=7)
        users = User.objects.filter(last_login__gte=since)
        return Response([ActiveUserSerializer(u).data for u in users])


class NewUsersReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="کاربران جدید ۷ روز اخیر",
        responses={200: NewUserSerializer(many=True)}
    )
    def get(self, request):
        since = timezone.now() - timedelta(days=7)
        users = User.objects.filter(date_joined__gte=since)
        return Response([NewUserSerializer(u).data for u in users])


class LocationStatsReportView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="آمار کاربران بر اساس مکان",
        responses={200: LocationStatsSerializer(many=True)}
    )
    def get(self, request):
        locations = Location.objects.annotate(
            student_count=Count("student_school"),
            driver_count=Count("driver_home")
        ).values("title", "student_count", "driver_count")

        result = [
            {
                "location_name": l["title"],
                "student_count": l["student_count"],
                "driver_count": l["driver_count"]
            } for l in locations
        ]
        return Response([LocationStatsSerializer(r).data for r in result])


# -----------------
# -----------------
# -----------------
