from users.serializers import FullUserProfileSerializer, CompleteProfileSerializer
from rest_framework.permissions import IsAuthenticated
import logging
from users.models import RoleTypes
from users.serializers import FullUserProfileSerializer
from rest_framework import permissions, status
from users.serializers import CompleteProfileSerializer
from rest_framework import status, permissions
from users.models import Referral
from django.utils.translation import gettext_lazy as _
from users.serializers import UserRegisterWithReferralSerializer
from rest_framework import status
from rest_framework import generics, permissions
import random
import hashlib
from datetime import timedelta
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from rest_framework import generics, permissions, status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from users.mixins import StandardResponseMixin
from users.models import (
    User, PhoneOTP, Referral,
    DriverProfile, ParentProfile, StudentProfile, SchoolProfile,
    TransportAdminProfile, EducationAdminProfile, SuperAdminProfile
)
from users.serializers import (
    SendOTPSerializer, OTPVerifySerializer, TokenResponseSerializer,
    ChangePhoneRequestSerializer, ChangePhoneVerifySerializer,
    ResendOTPSerializer, SetPasswordSerializer, PasswordResetSerializer,
    ReferralMineSerializer, ReferralInviterSerializer
)

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


class SendOTPView(StandardResponseMixin, APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=SendOTPSerializer,
        responses={200: openapi.Response('کد تایید ارسال شد')}
    )
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data['phone_number']
        raw_code = str(random.randint(1000, 9999))
        hashed_code = hashlib.sha256(raw_code.encode()).hexdigest()

        PhoneOTP.objects.filter(phone_number=phone, is_verified=False).delete()

        PhoneOTP.objects.update_or_create(
            phone_number=phone,
            defaults={
                'code': hashed_code,
                'is_verified': False,
                'created_at': timezone.now(),
                'failed_attempts': 0,
                'purpose': 'registration'
            }
        )

        # TODO: ارسال واقعی SMS با raw_code
        print(f" OTP for {phone} is {raw_code}")

        return self.standard_response(
            success=True,
            message="کد تأیید ارسال شد.",
            data={}
        )


class VerifyOTPView(StandardResponseMixin, generics.GenericAPIView):
    serializer_class = OTPVerifySerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        request_body=OTPVerifySerializer,
        responses={
            200: openapi.Response('ورود یا ثبت‌نام موفق', TokenResponseSerializer),
            400: 'کد تایید اشتباه یا منقضی شده',
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
            phone_number=phone, is_verified=False, purpose=purpose)

        try:
            otp_obj = otp_queryset.latest('created_at')
        except PhoneOTP.DoesNotExist:
            return self.error_response(message="کد تأیید معتبر نیست.")

        valid, msg = otp_obj.verify_code(otp)
        if not valid:
            return self.error_response(message=msg)

        otp_obj.is_verified = True
        otp_obj.save(update_fields=['is_verified'])

        # تغییر شماره موبایل
        if purpose == "change_phone":
            if not request.user.is_authenticated:
                return self.error_response("برای تغییر شماره ابتدا وارد شوید.", status.HTTP_403_FORBIDDEN)

            if User.objects.filter(phone_number=phone).exclude(id=request.user.id).exists():
                return self.error_response("این شماره قبلاً توسط کاربر دیگری استفاده شده است.", status.HTTP_400_BAD_REQUEST)

            request.user.phone_number = phone
            request.user.is_phone_verified = True
            request.user.save()

            return self.success_response(
                message="شماره تلفن با موفقیت تغییر یافت.",
                user=request.user
            )

        # ثبت‌نام یا ورود
        user, created = User.objects.get_or_create(phone_number=phone)

        if created:
            user.is_active = True
            user.is_phone_verified = True

            # نقش خاص برای شماره‌های خاص
            special_phones = getattr(settings, 'SPECIAL_ADMIN_PHONES', [])
            if phone in special_phones:
                user.system_role = User.SystemRole.SUPERADMIN
                user.is_staff = True
                user.is_superuser = True
            else:
                user.role = User.RoleTypes.USER

            # ثبت معرف
            if referral_code:
                inviter = User.objects.filter(
                    referral_code=referral_code).first()
                if inviter:
                    Referral.objects.create(
                        inviter=inviter,
                        invited=user,
                        referral_code_used=referral_code
                    )

            user.save()

        refresh = RefreshToken.for_user(user)
        profile_complete = all([user.first_name, user.last_name])

        token_data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'profile_complete': profile_complete,
        }

        token_serializer = TokenResponseSerializer(data=token_data)
        token_serializer.is_valid(raise_exception=True)

        return self.success_response(
            message="ورود یا ثبت‌نام با موفقیت انجام شد.",
            data=token_serializer.data,
            user=user
        )


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

        otp_code = str(random.randint(1000, 9999))
        hashed_code = hashlib.sha256(otp_code.encode()).hexdigest()

        PhoneOTP.objects.create(
            phone_number=new_phone,
            code=hashed_code,
            purpose='change_phone',
            is_verified=False,
            created_at=timezone.now(),
            failed_attempts=0
        )

        # TODO: ارسال پیامک واقعی به new_phone با otp_code
        print(f" OTP for changing phone {new_phone} is {otp_code}")

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
        otp_code = serializer.validated_data['otp_code']

        try:
            phone_otp = PhoneOTP.objects.filter(
                phone_number=new_phone, purpose='change_phone', is_verified=False).latest('created_at')
        except PhoneOTP.DoesNotExist:
            return self.error_response("کد تایید یافت نشد.", status.HTTP_404_NOT_FOUND)

        valid, message = phone_otp.verify_code(otp_code)
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
    permission_classes = [permissions.AllowAny]

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
        otp_code = serializer.validated_data['otp_code']
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

        hashed_input = hashlib.sha256(otp_code.encode()).hexdigest()
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

    @swagger_auto_schema(
        operation_summary="لیست کاربران دعوت‌شده توسط من",
        operation_description="کاربرانی که توسط این کاربر دعوت شده‌اند (رفرال‌های من).",
        responses={200: ReferralMineSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return Referral.objects.filter(inviter=self.request.user)


class MyInviterView(StandardResponseMixin, generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReferralInviterSerializer

    @swagger_auto_schema(
        operation_summary="مشاهده دعوت‌کننده من",
        operation_description="نمایش اطلاعات کاربری که این کاربر را دعوت کرده است.",
        responses={200: ReferralInviterSerializer()}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        return self.request.user.received_referral


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
        last = referrals.first().created_at if referrals.exists() else None
        data = {
            'count': count,
            'last_invited_at': last,
        }
        return self.success_response(data, message=_("آمار دعوت‌ها"))


class CompleteProfileView(StandardResponseMixin, APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = CompleteProfileSerializer(user)
        return self.standard_response(
            success=True,
            message="اطلاعات پروفایل کامل دریافت شد.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    def put(self, request):
        user = request.user
        serializer = CompleteProfileSerializer(
            user, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return self.standard_response(
                success=True,
                message="پروفایل با موفقیت بروزرسانی شد.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )
        else:
            return self.standard_response(
                success=False,
                message="خطا در داده‌های ورودی.",
                errors=serializer.errors,
                status_code=status.HTTP_400_BAD_REQUEST
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
        else:
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
