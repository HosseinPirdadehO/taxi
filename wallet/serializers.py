from datetime import timedelta
from django.db.models import Sum
from django.db import transaction
from django.utils import timezone
from wallet.models import WithdrawRequest, Wallet, WalletTransaction, WithdrawRequestStatus
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()


# واریز به کیف پول
class WalletDepositSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    source = serializers.CharField(
        required=False, allow_blank=True, max_length=100)
    description = serializers.CharField(
        required=False, allow_blank=True, max_length=256)

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("مبلغ باید بیشتر از صفر باشد.")
        return value


# برداشت از کیف پول
class WalletWithdrawSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    source = serializers.CharField(
        required=False, allow_blank=True, max_length=100)
    description = serializers.CharField(
        required=False, allow_blank=True, max_length=256)

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("مبلغ باید بیشتر از صفر باشد.")
        return value


# انتقال وجه بین کیف پول‌ها
class WalletTransferSerializer(serializers.Serializer):
    to_user_phone = serializers.CharField(max_length=20)
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    description = serializers.CharField(
        required=False, allow_blank=True, max_length=256)

    def validate(self, data):
        if data['amount'] <= 0:
            raise serializers.ValidationError("مبلغ باید بیشتر از صفر باشد.")
        try:
            to_user = User.objects.get(phone_number=data['to_user_phone'])
        except User.DoesNotExist:
            raise serializers.ValidationError("کاربر مقصد پیدا نشد.")
        if not hasattr(to_user, 'wallet'):
            raise serializers.ValidationError("کاربر مقصد کیف پول ندارد.")
        data['to_wallet'] = to_user.wallet
        return data


# درخواست برداشت
class WithdrawRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = WithdrawRequest
        fields = ['id', 'amount', 'status',
                  'requested_at', 'processed_at', 'admin_note']

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError(
                "مبلغ برداشت باید بیشتر از صفر باشد.")
        return value

    def validate(self, attrs):
        wallet = self.context['request'].user.wallet
        if wallet.balance < attrs['amount']:
            raise serializers.ValidationError(
                "موجودی کیف پول برای برداشت کافی نیست.")
        return attrs


# تغییر وضعیت درخواست برداشت توسط ادمین
class WithdrawRequestAdminUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = WithdrawRequest
        fields = ['status', 'admin_note']

    def validate_status(self, value):
        if value not in [WithdrawRequestStatus.APPROVED, WithdrawRequestStatus.REJECTED]:
            raise serializers.ValidationError(
                "وضعیت باید تایید شده یا رد شده باشد.")
        return value

    def update(self, instance, validated_data):
        if instance.status != WithdrawRequestStatus.PENDING:
            raise serializers.ValidationError(
                "این درخواست قبلاً پردازش شده است.")

        new_status = validated_data.get('status')
        admin_note = validated_data.get('admin_note', '')

        with transaction.atomic():
            instance.status = new_status
            instance.admin_note = admin_note
            instance.processed_at = timezone.now()

            if new_status == WithdrawRequestStatus.APPROVED:
                wallet = instance.wallet
                if wallet.balance < instance.amount:
                    raise serializers.ValidationError(
                        "موجودی کیف پول برای برداشت کافی نیست.")
                # کسر مبلغ از کیف پول
                wallet.withdraw(amount=instance.amount, source='withdraw_request',
                                description=f'تایید برداشت درخواست #{instance.id}')
                # تراکنش مرتبط
                WalletTransaction.create_transaction(
                    wallet=wallet,
                    transaction_type='withdraw',
                    amount=instance.amount,
                    previous_balance=wallet.balance + instance.amount,
                    description=f'برداشت تایید شده درخواست #{instance.id}'
                )

            instance.save()
        return instance


# تراکنش کیف پول
class WalletTransactionSerializer(serializers.ModelSerializer):
    transaction_type_display = serializers.CharField(
        source='get_transaction_type_display', read_only=True)
    status_display = serializers.CharField(
        source='get_status_display', read_only=True)
    created_at = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = WalletTransaction
        fields = [
            'id', 'transaction_type', 'transaction_type_display', 'amount', 'previous_balance',
            'description', 'status', 'status_display', 'source', 'reference_code', 'created_at'
        ]


#  امنیت و تنظیمات کیف پول
class WalletSummarySerializer(serializers.ModelSerializer):
    pin_code_expiring_soon = serializers.SerializerMethodField()

    class Meta:
        model = Wallet
        fields = [
            "balance",
            "withdrawn_today",
            "withdraw_limit_per_day",
            "currency",
            "status",
            "updated_at",
            "pin_code_expiry",
            "pin_code_expiring_soon",
        ]

    def get_pin_code_expiring_soon(self, obj):
        return obj.is_pin_code_expiring_soon()


class PinSetSerializer(serializers.Serializer):
    pin_code = serializers.CharField(
        write_only=True, min_length=4, max_length=10, trim_whitespace=True)
    expiry_days = serializers.IntegerField(
        default=30, min_value=1, max_value=365, required=False)


class PinVerifySerializer(serializers.Serializer):
    pin_code = serializers.CharField(
        write_only=True, min_length=4, max_length=10, trim_whitespace=True)


class DepositWithdrawSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    description = serializers.CharField(
        max_length=256, allow_blank=True, required=False)


class TransferSerializer(serializers.Serializer):
    to_user_id = serializers.UUIDField()
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    description = serializers.CharField(
        max_length=256, allow_blank=True, required=False)


# گزارشات و آمار مالی
class WalletStatsSerializer(serializers.Serializer):
    balance = serializers.DecimalField(max_digits=18, decimal_places=2)
    total_deposit = serializers.DecimalField(max_digits=18, decimal_places=2)
    total_withdraw = serializers.DecimalField(max_digits=18, decimal_places=2)
    total_transactions = serializers.IntegerField()


class WalletAnalyticsSerializer(serializers.Serializer):
    date = serializers.DateField()
    deposit = serializers.DecimalField(max_digits=18, decimal_places=2)
    withdraw = serializers.DecimalField(max_digits=18, decimal_places=2)
    transfer = serializers.DecimalField(max_digits=18, decimal_places=2)


# مدیریت ادمین
class AdminWalletSerializer(serializers.ModelSerializer):
    user_info = serializers.SerializerMethodField()

    class Meta:
        model = Wallet
        fields = '__all__'

    def get_user_info(self, obj):
        from users.serializers import FullUserProfileSerializer
        return FullUserProfileSerializer(obj.user).data


class AdminAdjustBalanceSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    operation = serializers.ChoiceField(choices=["increase", "decrease"])
    description = serializers.CharField(max_length=255)

    def validate(self, data):
        if data["amount"] <= 0:
            raise serializers.ValidationError("مقدار باید بیشتر از صفر باشد.")
        return data


class AdminTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = '__all__'


class ZarinpalPaymentInitiateSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=18, decimal_places=2)
    description = serializers.CharField(
        max_length=256, required=False, allow_blank=True)
    metadata = serializers.JSONField(required=False)

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("مبلغ باید بزرگتر از صفر باشد.")
        # سقف مبلغ، مثلاً ۱۰۰ میلیون تومان
        if value > 100_000_000:
            raise serializers.ValidationError(
                "مبلغ نباید بیشتر از ۱۰۰ میلیون تومان باشد.")
        return value

    def validate_metadata(self, value):
        # اگر بخوای محدودیت خاصی روی metadata بذاری
        if not isinstance(value, dict):
            raise serializers.ValidationError("metadata باید یک دیکشنری باشد.")
        return value


class ZarinpalVerifyQuerySerializer(serializers.Serializer):
    payment_id = serializers.UUIDField()
    Authority = serializers.CharField(max_length=100)
    Status = serializers.ChoiceField(choices=["OK", "NOK"])

    def validate_Status(self, value):
        if value.upper() not in ["OK", "NOK"]:
            raise serializers.ValidationError("وضعیت پرداخت نامعتبر است.")
        return value
