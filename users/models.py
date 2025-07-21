from django.utils.translation import gettext as _
from django.contrib.auth.models import BaseUserManager
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import hashlib
import random


class RoleTypes(models.TextChoices):
    SUPER_ADMIN = 'super_admin', 'سوپر ادمین'
    ADMIN = 'admin', 'ادمین'
    EDUCATION_ADMIN = 'education_admin', 'آموزش و پرورش'
    TRANSPORT_ADMIN = 'transport_admin', 'اداره حمل‌ونقل'
    SCHOOL_ADMIN = 'school_admin', 'مدیر مدرسه'
    PARENT = 'parent', 'والد'
    STUDENT = 'student', 'دانش‌آموز'
    DRIVER = 'driver', 'راننده'


class UserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('شماره موبایل الزامی است')

        # extra_fields.setdefault('username', phone_number)

        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', RoleTypes.SUPER_ADMIN)
        # extra_fields.setdefault('username', phone_number)

        if extra_fields.get('role') != RoleTypes.SUPER_ADMIN:
            raise ValueError('سوپر یوزر باید نقش SUPER_ADMIN داشته باشد.')

        return self.create_user(phone_number, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(
        max_length=15,
        unique=True,
        verbose_name=_("شماره موبایل")
    )
    is_phone_verified = models.BooleanField(
        default=False, verbose_name=_("تأیید شماره موبایل"))
    first_name = models.CharField(
        max_length=30, blank=True, verbose_name="نام")

    last_name = models.CharField(
        max_length=30, blank=True, verbose_name="نام خانوادگی")

    email = models.EmailField(blank=True, verbose_name="ایمیل")

    role = models.CharField(
        max_length=30,
        choices=RoleTypes.choices,
        default=RoleTypes.DRIVER,
        verbose_name=_("نقش کاربر")
    )

    national_code = models.CharField(
        max_length=10,
        unique=True,
        null=True,
        blank=True,
        verbose_name=_("کد ملی")
    )

    province = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        verbose_name=_("استان")
    )

    city = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        verbose_name=_("شهر")
    )

    birth_date = models.DateField(
        null=True,
        blank=True,
        verbose_name=_("تاریخ تولد")
    )

    referral_code = models.CharField(
        max_length=12,
        blank=True,
        null=True,
        unique=True,
        verbose_name=_("کد دعوت")
    )

    used_referral_code = models.CharField(
        max_length=12,
        blank=True,
        null=True,
        verbose_name=_("کد دعوت استفاده‌شده")
    )

    inviter = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invitees',
        verbose_name=_("دعوت‌کننده")
    )

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = self.generate_unique_referral_code()
        super().save(*args, **kwargs)

    def generate_unique_referral_code(self):
        length = 6
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        while True:
            code = ''.join(random.choices(chars, k=length))
            if not User.objects.filter(referral_code=code).exists():
                return code

    class Meta:
        verbose_name = _("کاربر")
        verbose_name_plural = _("کاربران")
        ordering = ['role', 'phone_number']

    def __str__(self):
        full_name = f"{self.first_name} {self.last_name}".strip()
        return f"{full_name or self.phone_number} ({self.get_role_display()})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.first_name or self.phone_number


class Location(models.Model):
    """
    مدل لوکیشن عمومی برای منزل، مدرسه، منطقه و ...
    """
    title = models.CharField(max_length=100, verbose_name=_("عنوان مکان"))
    address = models.TextField(verbose_name=_("آدرس"))
    latitude = models.DecimalField(
        max_digits=9, decimal_places=6, verbose_name=_("عرض جغرافیایی"))
    longitude = models.DecimalField(
        max_digits=9, decimal_places=6, verbose_name=_("طول جغرافیایی"))

    class Meta:
        verbose_name = _("مکان")
        verbose_name_plural = _("مکان‌ها")

    def __str__(self):
        return self.title


class DriverProfile(models.Model):
    """
    پروفایل اختصاصی راننده
    """

    TYPE_OF_CAR_CHOICES = [
        ('van', 'ون'),
        ('car', 'سواری'),
        ('minibus', 'مینی‌بوس'),
    ]

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر راننده"))
    plate_number = models.CharField(
        max_length=20, unique=True, verbose_name=_("شماره پلاک"))

    car_type = models.CharField(
        max_length=50,
        choices=TYPE_OF_CAR_CHOICES,
        default='car',
        verbose_name=_("نوع خودرو")
    )

    national_card_image = models.ImageField(
        upload_to="drivers/national_cards/",
        verbose_name=_("عکس کارت ملی"),
        null=True,
        blank=True,
    )

    profile_photo = models.ImageField(
        upload_to="drivers/photos/",
        null=True,
        blank=True,
        verbose_name=_("عکس پروفایل")
    )

    license_type = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name=_("نوع گواهینامه")
    )

    license_expiry_date = models.DateField(
        null=True,
        blank=True,
        verbose_name=_("تاریخ انقضای گواهینامه")
    )

    vehicle_insurance_image = models.ImageField(
        upload_to="drivers/insurance/",
        null=True,
        blank=True,
        verbose_name=_("بیمه خودرو")
    )

    is_verified = models.BooleanField(
        default=False,
        verbose_name=_("تأیید صلاحیت راننده")
    )

    rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        verbose_name=_("امتیاز راننده"),

    )

    class Meta:
        verbose_name = _("پروفایل راننده")
        verbose_name_plural = _("پروفایل‌های راننده")

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.plate_number}"


class ParentProfile(models.Model):
    """
    پروفایل والد برای ارتباط با دانش‌آموزان و راننده پیش‌فرض
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر والد"))
    relation_type = models.CharField(
        max_length=50,
        choices=[('father', _('پدر')), ('mother', _('مادر')),
                 ('guardian', _('قیم'))],
        default='father',
        verbose_name=_("نوع رابطه با دانش‌آموز")
    )
    default_driver = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="parent_default_driver",
        limit_choices_to={'role': 'driver'},
        verbose_name=_("راننده پیش‌فرض")
    )

    class Meta:
        verbose_name = _("پروفایل والد")
        verbose_name_plural = _("پروفایل‌های والد")

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.get_relation_type_display()}"


class StudentProfile(models.Model):
    """
    پروفایل دانش‌آموز با لوکیشن منزل و مدرسه و راننده پیش‌فرض
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر دانش‌آموز"))
    school_location = models.ForeignKey(
        Location, on_delete=models.SET_NULL, null=True, related_name="student_school", verbose_name=_("لوکیشن مدرسه"))
    home_location = models.ForeignKey(
        Location, on_delete=models.SET_NULL, null=True, related_name="student_home", verbose_name=_("لوکیشن منزل"))
    grade = models.CharField(max_length=20, verbose_name=_("پایه تحصیلی"))
    class_name = models.CharField(max_length=50, verbose_name=_("نام کلاس"))
    school_id_code = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_("کد دانش‌آموزی"))
    default_driver = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="student_default_driver",
        limit_choices_to={'role': 'driver'},
        verbose_name=_("راننده پیش‌فرض")
    )
    is_active = models.BooleanField(default=True, verbose_name=_("وضعیت فعال"))
    special_conditions = models.TextField(
        blank=True, null=True, verbose_name=_("شرایط خاص (اختیاری)"))

    class Meta:
        verbose_name = _("پروفایل دانش‌آموز")
        verbose_name_plural = _("پروفایل‌های دانش‌آموز")

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.grade} - {self.class_name}"


class SchoolProfile(models.Model):
    """
    پروفایل مدرسه یا مدیر مدرسه
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر مدرسه/مدیر"))
    school_name = models.CharField(max_length=150, verbose_name=_("نام مدرسه"))
    school_phone = models.CharField(
        max_length=20, verbose_name=_("شماره تماس مدرسه"))
    school_location = models.ForeignKey(
        Location, on_delete=models.SET_NULL, null=True, verbose_name=_("لوکیشن مدرسه"))
    school_code = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_("کد مدرسه"))
    start_time = models.TimeField(
        null=True, blank=True, verbose_name=_("ساعت شروع مدرسه"))
    end_time = models.TimeField(
        null=True, blank=True, verbose_name=_("ساعت پایان مدرسه"))
    school_type = models.CharField(
        max_length=50,
        choices=[('public', _('دولتی')), ('private', _(
            'غیردولتی')), ('special', _('استثنایی'))],
        default='public',
        verbose_name=_("نوع مدرسه")
    )

    class Meta:
        verbose_name = _("پروفایل مدرسه")
        verbose_name_plural = _("پروفایل‌های مدرسه")

    def __str__(self):
        return f"{self.school_name}"


class TransportAdminProfile(models.Model):
    """
    پروفایل اداره حمل و نقل با لیست مدارس زیرمجموعه
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر اداره حمل و نقل"))
    region_name = models.CharField(max_length=100, verbose_name=_("نام منطقه"))
    region_location = models.ForeignKey(
        Location, on_delete=models.SET_NULL, null=True, verbose_name=_("لوکیشن منطقه"))
    schools = models.ManyToManyField(
        SchoolProfile, blank=True, verbose_name=_("مدارس زیرمجموعه"))
    total_active_drivers = models.PositiveIntegerField(
        default=0, verbose_name=_("تعداد رانندگان فعال"))

    class Meta:
        verbose_name = _("پروفایل اداره حمل و نقل")
        verbose_name_plural = _("پروفایل‌های اداره حمل و نقل")

    def __str__(self):
        return f"{self.region_name}"


class EducationAdminProfile(models.Model):
    """
    پروفایل آموزش و پرورش با مدیریت دسترسی‌ها
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر آموزش و پرورش"))
    region_name = models.CharField(max_length=100, verbose_name=_("نام منطقه"))
    can_manage_permissions = models.BooleanField(
        default=True, verbose_name=_("مدیریت دسترسی‌ها"))

    class Meta:
        verbose_name = _("پروفایل آموزش و پرورش")
        verbose_name_plural = _("پروفایل‌های آموزش و پرورش")

    def __str__(self):
        return f"{self.region_name}"


class SuperAdminProfile(models.Model):
    """
    پروفایل سوپر ادمین با دسترسی کامل مدیریتی
    """
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, verbose_name=_("کاربر سوپر ادمین"))
    can_manage_all = models.BooleanField(
        default=True, verbose_name=_("دسترسی کامل مدیریتی"))
    can_view_logs = models.BooleanField(
        default=True, verbose_name=_("دسترسی مشاهده لاگ‌ها"))

    class Meta:
        verbose_name = _("پروفایل سوپر ادمین")
        verbose_name_plural = _("پروفایل‌های سوپر ادمین")

    def __str__(self):
        return f"سوپر ادمین: {self.user.get_full_name()}"


class PhoneOTP(models.Model):
    """
    مدل کد تأیید (OTP) برای ثبت‌نام، ورود و تغییر شماره موبایل
    """

    PURPOSE_CHOICES = (
        ('registration', _('ثبت‌نام')),
        ('login', _('ورود')),
        ('change_phone', _('تغییر شماره')),
        ('resend_otp', _('ارسال مجدد')),
    )

    phone_number = models.CharField(
        max_length=15, verbose_name=_("شماره موبایل"))
    code = models.CharField(max_length=128, verbose_name=_("کد هش‌شده"))
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name=_("زمان ایجاد"))
    is_verified = models.BooleanField(
        default=False, verbose_name=_("تأیید شده"))
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES,
                               default='registration', verbose_name=_("هدف کد"))
    failed_attempts = models.IntegerField(
        default=0, verbose_name=_("تلاش‌های ناموفق"))

    class Meta:
        verbose_name = _("کد تأیید")
        verbose_name_plural = _("کدهای تأیید")
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.phone_number} - {self.get_purpose_display()}"

    def is_expired(self):
        """بررسی منقضی شدن کد (۲ دقیقه اعتبار)"""
        expiration_duration = timedelta(minutes=2)
        return timezone.now() > self.created_at + expiration_duration

    def increase_failed_attempts(self):
        """افزایش تعداد تلاش‌های ناموفق و ذخیره"""
        self.failed_attempts += 1
        self.save(update_fields=['failed_attempts'])

    def verify_code(self, input_code):
        """
        بررسی صحت کد OTP ورودی
        برمی‌گرداند: (bool, پیام ترجمه شده)
        """

        if self.is_verified:
            return False, _("کد قبلاً استفاده شده است.")

        if self.failed_attempts >= 5:
            return False, _("تعداد تلاش‌های ناموفق بیش از حد مجاز است.")

        if self.is_expired():
            return False, _("کد منقضی شده است.")

        input_hash = hashlib.sha256(input_code.encode()).hexdigest()
        if input_hash != self.code:
            self.increase_failed_attempts()
            return False, _("کد تأیید اشتباه است.")

        return True, _("تأیید موفق بود.")


class Referral(models.Model):
    """
    مدل رفرال برای ثبت دعوت‌ها بین کاربران
    """
    inviter = models.ForeignKey(
        User,
        related_name='sent_referrals',
        on_delete=models.CASCADE,
        verbose_name=_("دعوت‌کننده")
    )
    invited = models.OneToOneField(
        User,
        related_name='received_referral',
        on_delete=models.CASCADE,
        verbose_name=_("دعوت‌شده")
    )
    referral_code_used = models.CharField(
        max_length=12,
        verbose_name=_("کد رفرال استفاده‌شده")
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("تاریخ دعوت")
    )

    class Meta:
        verbose_name = _("دعوت‌نامه")
        verbose_name_plural = _("دعوت‌نامه‌ها")
        ordering = ['-created_at']
        unique_together = ('inviter', 'invited')

    def __str__(self):
        inviter = self.inviter.get_full_name() or self.inviter.username
        invited = self.invited.get_full_name() or self.invited.username
        return f"{inviter} → {invited}"
