from .models import StudentProfile
from .models import DriverProfile
from .models import SchoolProfile
from .models import Referral, RoleTypes
from users.models import User, Referral
from users.models import DriverProfile
import string
import random
from users.models import (
    User, DriverProfile, ParentProfile, StudentProfile,
    SchoolProfile, TransportAdminProfile, EducationAdminProfile,
    SuperAdminProfile
)
from users.models import User, DriverProfile, ParentProfile, StudentProfile, SchoolProfile, TransportAdminProfile, EducationAdminProfile, SuperAdminProfile
from rest_framework import serializers
import re
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from users.models import User


def convert_to_english_digits(text):
    return text.translate(str.maketrans('۰۱۲۳۴۵۶۷۸۹', '0123456789'))


class SendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    permission_classes = [AllowAny]

    def validate_phone_number(self, value):
        value = convert_to_english_digits(value.strip())
        pattern = r'^(?:\+98|98|0)?9\d{9}$'
        if not re.match(pattern, value):
            raise serializers.ValidationError("شماره موبایل معتبر نیست.")
        return value


class OTPVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=4)
    purpose = serializers.CharField(required=False, allow_blank=True)
    referral_code = serializers.CharField(required=False, allow_blank=True)


class TokenResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    profile_complete = serializers.BooleanField()
    is_first_login = serializers.BooleanField()


class ChangePhoneRequestSerializer(serializers.Serializer):
    new_phone_number = serializers.CharField(max_length=15)


class ChangePhoneVerifySerializer(serializers.Serializer):
    new_phone_number = serializers.CharField(max_length=15)
    otp_code = serializers.CharField(max_length=6)


class ResendOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)


class SetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError(
                "رمز عبور و تکرار آن مطابقت ندارند.")
        return data


class PasswordResetSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    otp_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)


# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['id', 'phone_number', 'first_name', 'last_name', 'role']


class DriverProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriverProfile
        fields = [
            'plate_number',
            'car_type',
            'national_card_image',
            'profile_photo',
            'license_type',
            'license_expiry_date',
            'vehicle_insurance_image',
            'is_verified',
            'rating',
        ]


class ParentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParentProfile
        fields = [
            'relation_type',
            'default_driver',        # راننده پیش فرض (FK به User)
        ]


class StudentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = [
            'school_location',       # FK به Location
            'home_location',         # FK به Location
            'grade',
            'class_name',
            'school_id_code',
            'default_driver',
            'special_conditions',
            'is_active',
        ]


class TransportAdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransportAdminProfile
        fields = [
            'region_name',
            'region_location',
            'schools',               # ManyToManyField
            'total_active_drivers',
        ]


class EducationAdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationAdminProfile
        fields = [
            'region_name',
            'can_manage_permissions',
        ]


class SuperAdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuperAdminProfile
        fields = [
            'can_manage_all',
            'can_view_logs',
        ]


class SchoolAdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolProfile
        fields = [
            'school_name',
            'school_phone',
            'school_location',
            'school_code',
            'start_time',
            'end_time',
            'school_type',
        ]


class FullUserProfileSerializer(serializers.ModelSerializer):
    student_profile = StudentProfileSerializer(read_only=True)
    parent_profile = ParentProfileSerializer(read_only=True)
    driver_profile = DriverProfileSerializer(read_only=True)
    school_admin_profile = SchoolAdminProfileSerializer(read_only=True)
    transport_admin_profile = TransportAdminProfileSerializer(read_only=True)
    education_admin_profile = EducationAdminProfileSerializer(read_only=True)
    super_admin_profile = SuperAdminProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'phone_number', 'first_name', 'last_name', 'email', 'role',
            'national_code', 'province', 'city', 'birth_date',
            'driver_profile',
            'parent_profile',
            'student_profile',
            'school_admin_profile',
            'transport_admin_profile',
            'education_admin_profile',
            'super_admin_profile',
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)

        role_profile_map = {
            RoleTypes.STUDENT: 'student_profile',
            RoleTypes.PARENT: 'parent_profile',
            RoleTypes.DRIVER: 'driver_profile',
            RoleTypes.SCHOOL_ADMIN: 'school_admin_profile',
            RoleTypes.TRANSPORT_ADMIN: 'transport_admin_profile',
            RoleTypes.EDUCATION_ADMIN: 'education_admin_profile',
            RoleTypes.SUPER_ADMIN: 'super_admin_profile',
        }

        selected_profile_field = role_profile_map.get(instance.role)
        for field in role_profile_map.values():
            if field != selected_profile_field:
                data.pop(field, None)

        return data


class UserRegisterWithReferralSerializer(serializers.ModelSerializer):
    referral_code = serializers.CharField(
        required=False, allow_blank=True, write_only=True)

    class Meta:
        model = User
        fields = ['phone_number', 'first_name', 'last_name', 'referral_code']

    def validate_referral_code(self, value):
        if value:
            inviter = User.objects.filter(referral_code=value).first()
            if not inviter:
                raise serializers.ValidationError("کد معرف نامعتبر است.")
            self.context['inviter'] = inviter
        return value

    def create(self, validated_data):
        referral_code = validated_data.pop('referral_code', None)
        user = User.objects.create(**validated_data)
        user.is_active = True
        user.is_phone_verified = True
        user.save()

        # اگر کد معرف وجود داشت و کاربر قبلاً دعوت نشده بود، ثبت رفرال
        inviter = self.context.get('inviter', None)
        if inviter:
            if not hasattr(user, 'received_referral'):
                Referral.objects.create(
                    inviter=inviter,
                    invited=user,
                    referral_code_used=referral_code
                )
        return user

#  آمار دعوت‌های انجام‌شده توسط کاربر فعلی.س


class InvitedUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'first_name',
                  'last_name', 'role', 'date_joined']

#  لیست کسانی که کاربر فعلی دعوت کرده.


class ReferralMineSerializer(serializers.ModelSerializer):
    invited = InvitedUserSerializer()

    class Meta:
        model = Referral
        fields = ['invited', 'created_at']

# نمایش فردی که این کاربر را دعوت کرده است.


class ReferralInviterSerializer(serializers.ModelSerializer):
    inviter = InvitedUserSerializer()

    class Meta:
        model = Referral
        fields = ['inviter', 'created_at']


class CompleteProfileSerializer(serializers.ModelSerializer):
    driverprofile = DriverProfileSerializer(required=False)
    parentprofile = ParentProfileSerializer(required=False)
    studentprofile = StudentProfileSerializer(required=False)
    schoolprofile = SchoolAdminProfileSerializer(required=False)
    transportadminprofile = TransportAdminProfileSerializer(required=False)
    educationadminprofile = EducationAdminProfileSerializer(required=False)
    superadminprofile = SuperAdminProfileSerializer(required=False)

    class Meta:
        model = User
        fields = [
            'phone_number', 'first_name', 'last_name', 'email', 'role',
            'national_code', 'province', 'city', 'birth_date',
            'driverprofile', 'parentprofile', 'studentprofile', 'schoolprofile',
            'transportadminprofile', 'educationadminprofile', 'superadminprofile',
        ]
        # جلوگیری از تغییر  توسط کاربر
        read_only_fields = ['role', 'phone_number']

    def update(self, instance, validated_data):
        print("📥 validated_data:", validated_data)

        role_to_profile = {
            'driver': 'driverprofile',
            'parent': 'parentprofile',
            'student': 'studentprofile',
            'school_admin': 'schoolprofile',
            'transport_admin': 'transportadminprofile',
            'education_admin': 'educationadminprofile',
            'super_admin': 'superadminprofile',
        }

        profile_name = role_to_profile.get(instance.role)
        profile_data = validated_data.pop(
            profile_name, None) if profile_name else None

        user_fields = [
            'phone_number', 'first_name', 'last_name', 'email',
            'national_code', 'province', 'city', 'birth_date'
        ]
        for field in user_fields:
            if field in validated_data:
                print(
                    f"✅ Updating User field '{field}' = {validated_data[field]!r}")
                setattr(instance, field, validated_data[field])
            else:
                print(f"⚠️ User field '{field}' not in validated_data")

        instance.save()
        print(f"💾 User updated: {instance.first_name} {instance.last_name}")

        if profile_name and profile_data:
            profile_instance = getattr(instance, profile_name, None)

            serializer_map = {
                'driverprofile': DriverProfileSerializer,
                'parentprofile': ParentProfileSerializer,
                'studentprofile': SchoolAdminProfileSerializer,
                'schoolprofile': SchoolAdminProfileSerializer,
                'transportadminprofile': TransportAdminProfileSerializer,
                'educationadminprofile': EducationAdminProfileSerializer,
                'superadminprofile': SuperAdminProfileSerializer,
            }

            profile_model_map = {
                'driverprofile': DriverProfile,
                'parentprofile': ParentProfile,
                'studentprofile': StudentProfile,
                'schoolprofile': SchoolProfile,
                'transportadminprofile': TransportAdminProfile,
                'educationadminprofile': EducationAdminProfile,
                'superadminprofile': SuperAdminProfile,
            }

            if profile_instance:
                print(
                    f"🔄 Updating profile '{profile_name}' for user {instance.id}")
                profile_serializer = serializer_map[profile_name](
                    profile_instance, data=profile_data, partial=True
                )
                profile_serializer.is_valid(raise_exception=True)
                profile_serializer.save()
                print(f"💾 Profile '{profile_name}' updated successfully.")
            else:
                print(
                    f"➕ Creating profile '{profile_name}' for user {instance.id}")
                ProfileModel = profile_model_map.get(profile_name)
                if ProfileModel:
                    try:
                        ProfileModel.objects.create(
                            user=instance, **profile_data)
                        print(
                            f"💾 Profile '{profile_name}' created successfully.")
                    except Exception as e:
                        print(
                            f"❌ Error creating profile '{profile_name}': {e}")

        else:
            print("⚠️ No profile data to update or profile name not found.")

        return instance


# ----


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    inviter = serializers.PrimaryKeyRelatedField(read_only=True)
    date_joined = serializers.DateTimeField(
        format='%Y-%m-%d %H:%M:%S', read_only=True)

    class Meta:
        model = User
        fields = [
            'id',
            'phone_number',
            'is_phone_verified',
            'first_name',
            'last_name',
            'full_name',
            'email',
            'role',
            'national_code',
            'province',
            'city',
            'birth_date',
            'referral_code',
            'used_referral_code',
            'inviter',
            'is_active',
            'is_staff',
            'date_joined',
        ]
        read_only_fields = ['id', 'referral_code',
                            'inviter', 'is_staff', 'date_joined']

    def get_full_name(self, obj):
        return f"{obj.first_name or ''} {obj.last_name or ''}".strip()


# ------


# class UserInfoMixin(serializers.Serializer):
#     phone_number = serializers.CharField(
#         source='user.phone_number', read_only=True)
#     first_name = serializers.CharField(
#         source='user.first_name', read_only=True)
#     last_name = serializers.CharField(source='user.last_name', read_only=True)
#     email = serializers.EmailField(source='user.email', read_only=True)

# ------
# نکته کلیدی
# API مجزا
# کنترل کامل تغییر نقش و مدیریت وابستگی‌ها
# سیگنال‌ها
# خودکارسازی واکنش به تغییر نقش
# محدود کردن
# جلوگیری از تغییر نقش در API های عمومی
# مدیریت مجوز
# هماهنگی دسترسی‌ها با نقش جدید
# سرویس اختصاصی
# تمرکز منطق تغییر نقش در یک جای مشخص و قابل تست
