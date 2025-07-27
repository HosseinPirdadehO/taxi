from django.db import transaction
from wallet.models import Wallet
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
import logging

from .models import RoleTypes, Referral
from users.models import (
    User, DriverProfile, ParentProfile, StudentProfile,
    SchoolProfile, TransportAdminProfile, EducationAdminProfile, SuperAdminProfile
)

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


def get_referral_reward_amount():
    """
    تابع کمکی برای گرفتن مقدار پاداش دعوت از settings.py
    در صورت نبود مقدار در تنظیمات، مقدار پیش‌فرض ۵۰۰۰۰ برگشت داده می‌شود.
    """
    return getattr(settings, 'REFERRAL_REWARD_AMOUNT', 50000)


@receiver(post_save, sender=User)
def create_referral_code(sender, instance, created, **kwargs):
    if created and not instance.referral_code:
        instance.referral_code = instance.generate_unique_referral_code()
        # استفاده از update برای جلوگیری از اجرای مجدد سیگنال
        User.objects.filter(pk=instance.pk).update(
            referral_code=instance.referral_code)
        logger.info(f"Referral code created for user {instance.pk}")


@receiver(post_save, sender=User)
def handle_used_referral(sender, instance, created, **kwargs):
    if created and instance.used_referral_code:
        if not Referral.objects.filter(invited=instance).exists():
            try:
                inviter = User.objects.get(
                    referral_code=instance.used_referral_code)
                if inviter != instance:
                    Referral.objects.create(
                        inviter=inviter,
                        invited=instance,
                        referral_code_used=instance.used_referral_code
                    )
                    logger.info(
                        f"Referral created: inviter={inviter.pk} invited={instance.pk}")
            except User.DoesNotExist:
                logger.warning(
                    f"Invalid referral code used by user {instance.pk}: {instance.used_referral_code}")


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if not created:
        return

    role = instance.role
    profile_model = ROLE_PROFILE_MAP.get(role)

    if not profile_model:
        logger.warning(f"No profile model defined for role: {role}")
        return

    try:
        profile, is_created = profile_model.objects.get_or_create(
            user=instance)
        if is_created:
            logger.info(f"Profile created for user {instance.pk} as {role}")
        else:
            logger.info(
                f"Profile already exists for user {instance.pk} as {role}")
    except Exception as e:
        logger.error(f"Failed to create profile for user {instance.pk}: {e}")


@receiver(post_save, sender=User)
def create_wallet_and_reward(sender, instance, created, **kwargs):
    if not created:
        return

    # ۱- ساخت کیف پول جدید برای کاربر اگر قبلا نساخته شده بود
    wallet, wallet_created = Wallet.objects.get_or_create(user=instance)
    if wallet_created:
        logger.info(f"Wallet created for user {instance.pk}")

    # ۲- اگر کاربر با کد رفرال کسی ثبت‌نام کرده، به کیف پول دعوت‌کننده جایزه اضافه کن
    inviter = None
    if instance.used_referral_code:
        try:
            inviter = User.objects.get(
                referral_code=instance.used_referral_code)
        except User.DoesNotExist:
            inviter = None

    if inviter and inviter != instance:
        reward_amount = get_referral_reward_amount()
        try:
            inviter_wallet, _ = Wallet.objects.get_or_create(user=inviter)
            with transaction.atomic():
                inviter_wallet.deposit(
                    reward_amount,
                    description=f"پاداش دعوت از کاربر {instance.phone_number or instance.pk}"
                )
            logger.info(
                f"Rewarded inviter {inviter.pk} with {reward_amount} for inviting user {instance.pk}")
        except Exception as e:
            logger.error(f"Error rewarding inviter {inviter.pk}: {e}")
