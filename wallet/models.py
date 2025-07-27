from django.db import models
from django.db import models, transaction
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
import uuid
import hashlib


# ────── Enums ──────
class PaymentStatus(models.TextChoices):
    PENDING = 'pending', 'در انتظار'
    SUCCESS = 'success', 'موفق'
    FAILED = 'failed', 'ناموفق'
    CANCELLED = 'cancelled',


class WalletStatus(models.TextChoices):
    ACTIVE = 'active', _('فعال')
    FROZEN = 'frozen', _('مسدود شده')
    CLOSED = 'closed', _('بسته شده')


class TransactionType(models.TextChoices):
    DEPOSIT = 'deposit', _('واریز')
    WITHDRAW = 'withdraw', _('برداشت')
    TRANSFER = 'transfer', _('انتقال')
    PIN_SET = 'pin_set', _('تنظیم رمز')
    PIN_VERIFY = 'pin_verify', _('تایید رمز')
    REWARD = 'reward', _('پاداش')
    FEE = 'fee', _('کارمزد')
    REFUND = 'refund', _('بازگشت وجه')
    OTHER = 'other', _('سایر')


class TransactionStatus(models.TextChoices):
    PENDING = 'pending', _('در انتظار')
    COMPLETED = 'completed', _('کامل شده')
    FAILED = 'failed', _('ناموفق')
    REVERSED = 'reversed', _('برگشت خورده')


class WithdrawRequestStatus(models.TextChoices):
    PENDING = 'pending', _('در انتظار')
    APPROVED = 'approved', _('تأیید شده')
    REJECTED = 'rejected', _('رد شده')
    CANCELED = 'canceled',


class OperationStatus(models.TextChoices):
    SUCCESS = 'success', _('موفق')
    FAILURE = 'failure', _('ناموفق')


# ────── مدل کیف پول ──────
class Wallet(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet')

    balance = models.DecimalField(max_digits=18, decimal_places=2, default=0)
    currency = models.CharField(max_length=10, default='IRR')
    status = models.CharField(
        max_length=10, choices=WalletStatus.choices, default=WalletStatus.ACTIVE)

    withdraw_limit_per_day = models.DecimalField(
        max_digits=18, decimal_places=2, default=1000000)
    withdrawn_today = models.DecimalField(
        max_digits=18, decimal_places=2, default=0)
    last_withdraw_reset = models.DateTimeField(default=timezone.now)

    pin_code_hash = models.CharField(max_length=256, blank=True, null=True)
    pin_code_expiry = models.DateTimeField(null=True, blank=True)
    failed_pin_attempts = models.IntegerField(default=0)
    last_failed_attempt = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    PIN_LOCK_THRESHOLD = 5
    PIN_LOCK_DURATION_MINUTES = 5

    def __str__(self):
        return f"Wallet({self.user}, Balance: {self.balance} {self.currency})"

    def check_active(self):
        if self.status != WalletStatus.ACTIVE:
            raise ValidationError("کیف پول فعال نیست.")

    def reset_withdraw_if_needed(self):
        if timezone.now().date() != self.last_withdraw_reset.date():
            self.withdrawn_today = 0
            self.last_withdraw_reset = timezone.now()
            self.save(update_fields=['withdrawn_today', 'last_withdraw_reset'])

    def deposit(self, amount, source='', description=''):
        self.check_active()
        if amount <= 0:
            raise ValidationError("مبلغ باید مثبت باشد.")

        with transaction.atomic():
            self.refresh_from_db()
            previous = self.balance
            self.balance += amount
            self.save(update_fields=['balance'])

            WalletTransaction.create_transaction(
                wallet=self,
                transaction_type=TransactionType.DEPOSIT,
                amount=amount,
                previous_balance=previous,
                source=source,
                description=description,
            )

        WalletOperationLog.objects.create(
            wallet=self,
            operation_type=TransactionType.DEPOSIT,
            amount=amount,
            status=OperationStatus.SUCCESS,
            message='واریز با موفقیت انجام شد.'
        )

    def withdraw(self, amount, source='', description=''):
        self.check_active()
        if amount <= 0:
            raise ValidationError("مبلغ باید مثبت باشد.")

        with transaction.atomic():
            self.refresh_from_db()
            self.reset_withdraw_if_needed()

            if self.balance < amount:
                raise ValidationError("موجودی کافی نیست.")
            if self.withdrawn_today + amount > self.withdraw_limit_per_day:
                raise ValidationError("سقف برداشت روزانه رد شده است.")

            previous = self.balance
            self.balance -= amount
            self.withdrawn_today += amount
            self.save(update_fields=['balance', 'withdrawn_today'])

            WalletTransaction.create_transaction(
                wallet=self,
                transaction_type=TransactionType.WITHDRAW,
                amount=amount,
                previous_balance=previous,
                source=source,
                description=description,
            )

        WalletOperationLog.objects.create(
            wallet=self,
            operation_type=TransactionType.WITHDRAW,
            amount=amount,
            status=OperationStatus.SUCCESS,
            message='برداشت با موفقیت انجام شد.'
        )

    def transfer_to(self, to_wallet, amount, description=''):
        self.check_active()
        to_wallet.check_active()

        if self == to_wallet:
            raise ValidationError("انتقال به خود مجاز نیست.")
        if amount <= 0:
            raise ValidationError("مبلغ باید مثبت باشد.")

        with transaction.atomic():
            self.withdraw(amount, source='transfer',
                          description=f'انتقال به {to_wallet.user}')
            to_wallet.deposit(amount, source='transfer',
                              description=f'انتقال از {self.user}')

            WalletTransferHistory.objects.create(
                from_wallet=self,
                to_wallet=to_wallet,
                amount=amount,
                description=description
            )

        WalletOperationLog.objects.create(
            wallet=self,
            operation_type=TransactionType.TRANSFER,
            amount=amount,
            status=OperationStatus.SUCCESS,
            message=f'انتقال به {to_wallet.user} انجام شد.'
        )

    def set_pin_code(self, raw_pin, expiry_days=30):
        self.pin_code_hash = make_password(raw_pin)
        self.pin_code_expiry = timezone.now() + timedelta(days=expiry_days)
        self.failed_pin_attempts = 0
        self.last_failed_attempt = None
        self.save(update_fields=[
            'pin_code_hash', 'pin_code_expiry',
            'failed_pin_attempts', 'last_failed_attempt'
        ])

    def check_pin_code(self, raw_pin):
        now = timezone.now()

        # بررسی قفل موقت در صورت تلاش‌های زیاد
        if self.failed_pin_attempts >= self.PIN_LOCK_THRESHOLD:
            if self.last_failed_attempt and (now - self.last_failed_attempt) < timedelta(minutes=self.PIN_LOCK_DURATION_MINUTES):
                return {
                    'success': False,
                    'message': f'کیف پول به علت تلاش‌های زیاد، برای {self.PIN_LOCK_DURATION_MINUTES} دقیقه قفل شده است.'
                }
            else:
                self.failed_pin_attempts = 0
                self.save(update_fields=['failed_pin_attempts'])

        if not self.pin_code_hash or not self.pin_code_expiry:
            return {'success': False, 'message': 'رمز کیف پول تنظیم نشده است.'}
        if now > self.pin_code_expiry:
            return {'success': False, 'message': 'رمز کیف پول منقضی شده است.'}

        if check_password(raw_pin, self.pin_code_hash):
            if self.failed_pin_attempts > 0:
                self.failed_pin_attempts = 0
                self.save(update_fields=['failed_pin_attempts'])
            return {'success': True, 'message': 'رمز صحیح است.'}
        else:
            self.failed_pin_attempts += 1
            self.last_failed_attempt = now
            self.save(update_fields=[
                      'failed_pin_attempts', 'last_failed_attempt'])
            attempts_left = max(
                0, self.PIN_LOCK_THRESHOLD - self.failed_pin_attempts)
            return {'success': False, 'message': f'رمز اشتباه است. {attempts_left} تلاش باقی مانده.'}

    def is_pin_code_expiring_soon(self, days=5):
        if not self.pin_code_expiry:
            return True
        return (self.pin_code_expiry - timezone.now()).days <= days

    def get_summary(self):
        return {
            "balance": self.balance,
            "withdrawn_today": self.withdrawn_today,
            "limit": self.withdraw_limit_per_day,
            "currency": self.currency,
            "status": self.status,
            "updated_at": self.updated_at,
            "pin_code_expiry": self.pin_code_expiry,
            "pin_code_expiring_soon": self.is_pin_code_expiring_soon(),
        }

    class Meta:
        verbose_name = " کیف پول"
        verbose_name_plural = " کیف پول"

# ────── تراکنش‌ها ──────


class WalletTransaction(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(
        max_length=20, choices=TransactionType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    previous_balance = models.DecimalField(
        max_digits=18, decimal_places=2, null=True, blank=True)
    description = models.CharField(max_length=256, blank=True)
    status = models.CharField(
        max_length=20, choices=TransactionStatus.choices, default=TransactionStatus.PENDING)
    source = models.CharField(max_length=100, blank=True, null=True)
    reference_code = models.CharField(
        max_length=100, unique=True, blank=True, null=True)
    integrity_hash = models.CharField(max_length=256, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_reversed = models.BooleanField(default=False)
    reversed_at = models.DateTimeField(null=True, blank=True)
    from_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                  related_name='sent_wallet_transactions', on_delete=models.SET_NULL)
    to_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                related_name='received_wallet_transactions', on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.wallet.user} - {self.transaction_type} - {self.amount} {self.wallet.currency}"

    def save(self, *args, **kwargs):
        if not self.reference_code:
            self.reference_code = str(uuid.uuid4())
        self.integrity_hash = self.generate_integrity_hash()
        super().save(*args, **kwargs)

    def generate_integrity_hash(self):
        raw = f"{self.wallet.user_id}-{self.amount}-{self.transaction_type}-{self.created_at}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def create_transaction(cls, wallet, transaction_type, amount, previous_balance=None, description='', source='', from_user=None, to_user=None):
        return cls.objects.create(
            wallet=wallet,
            transaction_type=transaction_type,
            amount=amount,
            previous_balance=previous_balance,
            description=description,
            status=TransactionStatus.COMPLETED,
            source=source,
            from_user=from_user,
            to_user=to_user
        )

    class Meta:
        verbose_name = "تراکنش کیف پول"
        verbose_name_plural = "تراکنش‌های کیف پول"

# ────── لاگ خطا ──────


class WalletErrorLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='error_logs')
    error_type = models.CharField(max_length=100)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.wallet.user} - {self.error_type} @ {self.created_at}"


# ────── درخواست برداشت ──────
class WithdrawRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='withdraw_requests')
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    status = models.CharField(
        max_length=20, choices=WithdrawRequestStatus.choices, default=WithdrawRequestStatus.PENDING)
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(blank=True, null=True)
    admin_note = models.TextField(blank=True)

    def clean(self):
        if self.amount <= 0:
            raise ValidationError("مبلغ برداشت باید بزرگتر از صفر باشد.")
        if self.wallet.balance < self.amount:
            raise ValidationError("موجودی کیف پول برای این برداشت کافی نیست.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"WithdrawRequest({self.wallet.user}, {self.amount}, {self.status})"

    class Meta:
        verbose_name = "درخواست برداشت"
        verbose_name_plural = "درخواست‌های برداشت"


# ────── تاریخچه انتقال ──────
class WalletTransferHistory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    from_wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='outgoing_transfers')
    to_wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='incoming_transfers')
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    description = models.CharField(max_length=256, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transfer({self.from_wallet.user} -> {self.to_wallet.user}, {self.amount})"

    class Meta:
        verbose_name = "تاریخچه انتقال"
        verbose_name_plural = "تاریخچه انتقال‌ها"


# ────── لاگ عملیات کیف پول ──────
class WalletOperationLog(models.Model):
    id = models.BigAutoField(primary_key=True)
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name='operation_logs')
    operation_type = models.CharField(
        max_length=20, choices=TransactionType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2, null=True,
                                 blank=True, help_text="مبلغ مربوط به عملیات (در صورت وجود)")
    status = models.CharField(
        max_length=10, choices=OperationStatus.choices, default=OperationStatus.SUCCESS)
    message = models.TextField(
        blank=True, help_text="توضیح یا پیام مرتبط با عملیات")
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, help_text="آدرس IP درخواست‌دهنده")
    user_agent = models.TextField(
        null=True, blank=True, help_text="اطلاعات مرورگر یا کلاینت")
    metadata = models.JSONField(
        null=True, blank=True, help_text="اطلاعات اضافی دلخواه (برای توسعه)")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "گزارش عملیات کیف پول"
        verbose_name_plural = "گزارش‌های عملیات کیف پول"

    def __str__(self):
        return f"{self.wallet.user} | {self.operation_type} | {self.status} | {self.amount or '-'}"

    class Meta:
        verbose_name = "گزارش عملیات کیف پول"
        verbose_name_plural = "گزارش‌های عملیات کیف پول"


class ZarinPayment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(
        'wallet.Wallet', on_delete=models.CASCADE, related_name='external_payments')
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    authority = models.CharField(
        max_length=100, unique=True, null=True, blank=True)  # کد مرجع زرین پال
    payment_url = models.URLField(null=True, blank=True)
    status = models.CharField(
        max_length=20, choices=PaymentStatus.choices, default=PaymentStatus.PENDING, db_index=True)
    description = models.CharField(max_length=256, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    callback_data = models.JSONField(null=True, blank=True)
    # فیلد اختیاری برای ثبت آی‌پی یا اطلاعات اضافی
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return f"{self.wallet.user} - {self.amount} - {self.get_status_display()}"

    def is_success(self):
        return self.status == PaymentStatus.SUCCESS

    def is_pending(self):
        return self.status == PaymentStatus.PENDING

    def is_failed(self):
        return self.status == PaymentStatus.FAILED

    class Meta:
        ordering = ['-created_at']
        verbose_name = "پرداخت زرین پال"
        verbose_name_plural = "پرداخت‌های زرین پال"
