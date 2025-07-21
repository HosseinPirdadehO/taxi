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
        fields = ('id', 'user', 'national_code', 'job_title')
        export_order = ('id', 'user', 'national_code', 'job_title')


class StudentProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = StudentProfile
        fields = ('id', 'user', 'grade', 'school_name')
        export_order = ('id', 'user', 'grade', 'school_name')


class DriverProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = DriverProfile
        fields = ('id', 'user', 'license_number', 'vehicle_type')
        export_order = ('id', 'user', 'license_number', 'vehicle_type')


class SchoolProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = SchoolProfile
        fields = ('id', 'user', 'school_name', 'address', 'city')
        export_order = ('id', 'user', 'school_name', 'address', 'city')


class TransportAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = TransportAdminProfile
        fields = ('id', 'user', 'region', 'employee_code')
        export_order = ('id', 'user', 'region', 'employee_code')


class EducationAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = EducationAdminProfile
        fields = ('id', 'user', 'region', 'employee_code')
        export_order = ('id', 'user', 'region', 'employee_code')


class SuperAdminProfileResource(resources.ModelResource):
    user = UserForeignKeyField()

    class Meta:
        model = SuperAdminProfile
        fields = ('id', 'user', 'title')
        export_order = ('id', 'user', 'title')
