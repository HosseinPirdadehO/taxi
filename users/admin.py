from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from import_export import resources
from .models import (
    User, DriverProfile, ParentProfile, StudentProfile,
    SchoolProfile, TransportAdminProfile, EducationAdminProfile,
    SuperAdminProfile, Location, PhoneOTP, Referral
)

# ---------------------- RESOURCES ---------------------- #


class UserResource(resources.ModelResource):
    class Meta:
        model = User
        fields = (
            'id', 'phone_number', 'first_name', 'last_name', 'role',
            'province', 'city', 'birth_date', 'is_active', 'date_joined',
            'referral_code', 'used_referral_code', 'inviter'
        )


class DriverProfileResource(resources.ModelResource):
    class Meta:
        model = DriverProfile
        fields = '__all__'


class ParentProfileResource(resources.ModelResource):
    class Meta:
        model = ParentProfile
        fields = '__all__'


class StudentProfileResource(resources.ModelResource):
    class Meta:
        model = StudentProfile
        fields = '__all__'


class SchoolProfileResource(resources.ModelResource):
    class Meta:
        model = SchoolProfile
        fields = '__all__'


class TransportAdminProfileResource(resources.ModelResource):
    class Meta:
        model = TransportAdminProfile
        fields = '__all__'


class EducationAdminProfileResource(resources.ModelResource):
    class Meta:
        model = EducationAdminProfile
        fields = '__all__'


class SuperAdminProfileResource(resources.ModelResource):
    class Meta:
        model = SuperAdminProfile
        fields = '__all__'


class LocationResource(resources.ModelResource):
    class Meta:
        model = Location
        fields = '__all__'


class PhoneOTPResource(resources.ModelResource):
    class Meta:
        model = PhoneOTP
        fields = '__all__'


class ReferralResource(resources.ModelResource):
    class Meta:
        model = Referral
        fields = '__all__'


# ---------------------- ADMIN CLASSES ---------------------- #

@admin.register(User)
class UserAdmin(ImportExportModelAdmin):
    resource_class = UserResource
    list_display = [
        'phone_number', 'first_name', 'last_name', 'role',
        'province', 'city', 'is_active', 'date_joined'
    ]
    list_filter = ['role', 'province', 'city', 'is_active']
    search_fields = ['phone_number', 'first_name', 'last_name',
                     'national_code', 'referral_code', 'used_referral_code']
    ordering = ['role', 'phone_number']

    def get_export_queryset(self, request):
        # فقط داده‌های فعال را اکسپورت کند
        return super().get_export_queryset(request).filter(is_active=True)


@admin.register(DriverProfile)
class DriverProfileAdmin(ImportExportModelAdmin):
    resource_class = DriverProfileResource
    list_display = ['user', 'plate_number',
                    'car_type', 'is_verified', 'rating']
    list_filter = ['is_verified', 'car_type']
    search_fields = ['user__phone_number', 'user__first_name', 'plate_number']
    autocomplete_fields = ['user']


@admin.register(ParentProfile)
class ParentProfileAdmin(ImportExportModelAdmin):
    resource_class = ParentProfileResource
    list_display = ['user', 'relation_type', 'default_driver']
    search_fields = ['user__phone_number',
                     'user__first_name', 'user__last_name']
    autocomplete_fields = ['user', 'default_driver']


@admin.register(StudentProfile)
class StudentProfileAdmin(ImportExportModelAdmin):
    resource_class = StudentProfileResource
    list_display = ['user', 'grade', 'class_name', 'is_active']
    list_filter = ['grade', 'is_active']
    search_fields = ['user__phone_number', 'user__first_name',
                     'user__last_name', 'school_id_code']
    autocomplete_fields = ['user', 'default_driver',
                           'home_location', 'school_location']


@admin.register(SchoolProfile)
class SchoolProfileAdmin(ImportExportModelAdmin):
    resource_class = SchoolProfileResource
    list_display = ['user', 'school_name', 'school_phone', 'school_type']
    list_filter = ['school_type']
    search_fields = ['school_name', 'school_code']
    autocomplete_fields = ['user', 'school_location']


@admin.register(TransportAdminProfile)
class TransportAdminProfileAdmin(ImportExportModelAdmin):
    resource_class = TransportAdminProfileResource
    list_display = ['user', 'region_name', 'total_active_drivers']
    autocomplete_fields = ['user', 'region_location', 'schools']


@admin.register(EducationAdminProfile)
class EducationAdminProfileAdmin(ImportExportModelAdmin):
    resource_class = EducationAdminProfileResource
    list_display = ['user', 'region_name', 'can_manage_permissions']
    autocomplete_fields = ['user']


@admin.register(SuperAdminProfile)
class SuperAdminProfileAdmin(ImportExportModelAdmin):
    resource_class = SuperAdminProfileResource
    list_display = ['user', 'can_manage_all', 'can_view_logs']
    autocomplete_fields = ['user']


@admin.register(Location)
class LocationAdmin(ImportExportModelAdmin):
    resource_class = LocationResource
    list_display = ['title', 'latitude', 'longitude']
    search_fields = ['title']


@admin.register(PhoneOTP)
class PhoneOTPAdmin(ImportExportModelAdmin):
    resource_class = PhoneOTPResource
    list_display = ['phone_number', 'purpose', 'is_verified', 'created_at']
    list_filter = ['is_verified', 'purpose']
    search_fields = ['phone_number']


@admin.register(Referral)
class ReferralAdmin(ImportExportModelAdmin):
    resource_class = ReferralResource
    list_display = ['inviter', 'invited', 'referral_code_used', 'created_at']
    search_fields = ['inviter__phone_number',
                     'invited__phone_number', 'referral_code_used']
    ordering = ['-created_at']
