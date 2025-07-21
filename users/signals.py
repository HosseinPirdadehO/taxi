from users.models import (
    User, DriverProfile, ParentProfile, StudentProfile,
    SchoolProfile, TransportAdminProfile, EducationAdminProfile, SuperAdminProfile
)
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from .models import RoleTypes, User, Referral


@receiver(post_save, sender=User)
def create_referral_code(sender, instance, created, **kwargs):
    """
    اگر کاربر تازه ساخته شده و referral_code نداشته باشد، یک کد یکتا تولید می‌شود.
    """
    if created and not instance.referral_code:
        instance.referral_code = instance.generate_unique_referral_code()
        instance.save(update_fields=['referral_code'])


@receiver(post_save, sender=User)
def handle_used_referral(sender, instance, created, **kwargs):
    """
    اگر کاربر با کد دعوت ثبت‌نام کرده باشد، رابطه referral ساخته می‌شود.
    """
    if created and instance.used_referral_code and not hasattr(instance, 'received_referral'):
        try:
            inviter = User.objects.get(
                referral_code=instance.used_referral_code)
            if inviter != instance:
                Referral.objects.create(
                    inviter=inviter,
                    invited=instance,
                    referral_code_used=instance.used_referral_code
                )
        except User.DoesNotExist:
            # در صورت نامعتبر بودن کد، نادیده گرفته می‌شود
            pass


logger = logging.getLogger(__name__)


ROLE_PROFILE_MAP = {
    RoleTypes.DRIVER: DriverProfile,
    RoleTypes.PARENT: ParentProfile,
    RoleTypes.STUDENT: StudentProfile,
    RoleTypes.SCHOOL_ADMIN: SchoolProfile,
    RoleTypes.TRANSPORT_ADMIN: TransportAdminProfile,
    RoleTypes.EDUCATION_ADMIN: EducationAdminProfile,
    RoleTypes.SUPER_ADMIN: SuperAdminProfile,
}


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if not created:
        return

    role = instance.role
    profile_model = ROLE_PROFILE_MAP.get(role)

    if not profile_model:
        logger.warning(f"⛔ No profile model defined for role: {role}")
        return

    try:
        profile, is_created = profile_model.objects.get_or_create(
            user=instance)

        if is_created:
            logger.info(f"✅ Profile created for user {instance.id} as {role}")
        else:
            logger.info(
                f"ℹ️ Profile already exists for user {instance.id} as {role}")

    except Exception as e:
        logger.error(f"❌ Failed to create profile for user {instance.id}: {e}")
