from import_export import resources, fields
from import_export.widgets import ForeignKeyWidget
from django.contrib.auth import get_user_model
from .models import (
    ParentProfile,
    StudentProfile,
    DriverProfile,
    SchoolProfile,
    TransportAdminProfile,
    EducationAdminProfile,
    SuperAdminProfile
)

User = get_user_model()


class UserForeignKeyField(fields.Field):
    """
    Custom field to display username instead of user ID
    """

    def __init__(self, *args, **kwargs):
        kwargs['attribute'] = 'user'
        kwargs['column_name'] = 'user__username'
        kwargs['widget'] = ForeignKeyWidget(User, 'username')
        super().__init__(*args, **kwargs)


class ParentProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = ParentProfile
        fields = ('id', 'user', 'relation_type')
        export_order = fields


class StudentProfileResource(resources.ModelResource):
    user = UserForeignKeyField()
    school_location = fields.Field(
        attribute='school_location__title', column_name='school_location')
    home_location = fields.Field(
        attribute='home_location__title', column_name='home_location')

    class Meta:
        model = StudentProfile
        fields = (
            'id', 'user', 'grade', 'class_name',
            'school_id_code', 'school_location', 'home_location',
            'is_active', 'special_conditions'
        )
        export_order = fields


class DriverProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = DriverProfile
        fields = (
            'id', 'user', 'plate_number', 'car_type',
            'license_type', 'license_expiry_date', 'is_verified', 'rating'
        )
        export_order = fields


class SchoolProfileResource(resources.ModelResource):
    user = UserForeignKeyField()
    school_location = fields.Field(
        attribute='school_location__title', column_name='school_location')

    class Meta:
        model = SchoolProfile
        fields = (
            'id', 'user', 'school_name', 'school_phone',
            'school_code', 'school_type', 'school_location',
            'start_time', 'end_time'
        )
        export_order = fields


class TransportAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()
    region_location = fields.Field(
        attribute='region_location__title', column_name='region_location')

    class Meta:
        model = TransportAdminProfile
        fields = (
            'id', 'user', 'region_name',
            'region_location', 'total_active_drivers'
        )
        export_order = fields


class EducationAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = EducationAdminProfile
        fields = ('id', 'user', 'region_name', 'can_manage_permissions')
        export_order = fields


class SuperAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = SuperAdminProfile
        fields = ('id', 'user', 'can_manage_all', 'can_view_logs')
        export_order = fields
