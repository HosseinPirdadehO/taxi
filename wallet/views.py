# Django / DRF
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum, Count
from django.db.models.functions import TruncDate
from datetime import timedelta
from django.shortcuts import render
from rest_framework import generics, permissions, filters, status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import (
    Wallet, ZarinPayment, WalletTransaction,
    TransactionType, OperationStatus,
    WalletOperationLog, WithdrawRequest,
    WithdrawRequestStatus
)
from .serializers import (
    WalletDepositSerializer,
    WalletWithdrawSerializer,
    WalletTransferSerializer,
    WithdrawRequestAdminUpdateSerializer,
    WithdrawRequestSerializer,
    WalletTransactionSerializer,
    WalletSummarySerializer,
    PinSetSerializer,
    PinVerifySerializer,
    DepositWithdrawSerializer,
    TransferSerializer,
    WalletStatsSerializer,
    WalletAnalyticsSerializer,
    AdminWalletSerializer,
    AdminTransactionSerializer,
    AdminAdjustBalanceSerializer,
    ZarinpalPaymentInitiateSerializer,
    ZarinpalVerifyQuerySerializer
)

import requests
from .mixins import WalletResponseMixin


class WalletDetailView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="دریافت اطلاعات کیف پول کاربر",
        responses={200: openapi.Response('جزئیات کیف پول')}
    )
    def get(self, request):
        wallet = Wallet.objects.get(user=request.user)
        return self.success_response(
            message="اطلاعات کیف پول بازیابی شد.",
            wallet=wallet,
            data=wallet.get_summary()
        )


class WalletWithdrawView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=WalletWithdrawSerializer,
        operation_summary="برداشت از کیف پول",
        responses={200: openapi.Response('برداشت موفق')}
    )
    def post(self, request):
        serializer = WalletWithdrawSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        wallet = Wallet.objects.get(user=request.user)
        try:
            wallet.withdraw(
                amount=serializer.validated_data['amount'],
                source=serializer.validated_data.get('source', ''),
                description=serializer.validated_data.get('description', ''),
            )
            return self.success_response(
                message="برداشت با موفقیت انجام شد.",
                wallet=wallet,
                data={"balance": wallet.balance}
            )
        except Exception as e:
            return self.error_response(
                message=str(e),
                wallet=wallet
            )


class WalletTransferView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=WalletTransferSerializer,
        operation_summary="انتقال وجه به کیف پول دیگر",
        responses={200: openapi.Response('انتقال موفق')}
    )
    def post(self, request):
        serializer = WalletTransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from_wallet = Wallet.objects.get(user=request.user)
        to_wallet = serializer.validated_data['to_wallet']
        amount = serializer.validated_data['amount']
        description = serializer.validated_data.get('description', '')

        try:
            from_wallet.transfer_to(to_wallet, amount, description=description)
            return self.success_response(
                message="انتقال با موفقیت انجام شد.",
                wallet=from_wallet,
                data={"balance": from_wallet.balance}
            )
        except Exception as e:
            return self.error_response(
                message=str(e),
                wallet=from_wallet
            )


class WithdrawRequestCreateView(WalletResponseMixin, generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WithdrawRequestSerializer

    @swagger_auto_schema(
        operation_summary="ثبت درخواست برداشت",
        request_body=WithdrawRequestSerializer,
        responses={201: openapi.Response("درخواست ثبت شد")}
    )
    def perform_create(self, serializer):
        serializer.save(wallet=self.request.user.wallet)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        return self.success_response(
            message="درخواست برداشت با موفقیت ثبت شد.",
            wallet=request.user.wallet,
            data=response.data
        )


class WithdrawRequestListView(WalletResponseMixin, generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WithdrawRequestSerializer

    @swagger_auto_schema(
        operation_summary="لیست درخواست‌های برداشت",
        responses={200: WithdrawRequestSerializer(many=True)}
    )
    def get_queryset(self):
        return WithdrawRequest.objects.filter(wallet=self.request.user.wallet).order_by('-requested_at')

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        return self.success_response(
            message="لیست درخواست‌های برداشت دریافت شد.",
            wallet=request.user.wallet,
            data=response.data
        )
    permission_classes = [permissions.IsAdminUser]


class WithdrawRequestAdminUpdateView(WalletResponseMixin, generics.UpdateAPIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = WithdrawRequestAdminUpdateSerializer
    queryset = WithdrawRequest.objects.filter(
        status=WithdrawRequestStatus.PENDING)

    @swagger_auto_schema(
        operation_summary="بروزرسانی درخواست برداشت توسط ادمین",
        request_body=WithdrawRequestAdminUpdateSerializer,
        responses={200: openapi.Response("درخواست پردازش شد")}
    )
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return self.success_response(
            message="درخواست برداشت با موفقیت پردازش شد.",
            data=response.data
        )


class WalletTransactionListView(WalletResponseMixin, generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WalletTransactionSerializer
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    search_fields = ['description', 'source', 'reference_code']
    ordering_fields = ['created_at', 'amount']
    ordering = ['-created_at']

    @swagger_auto_schema(
        operation_summary="لیست تراکنش‌های کیف پول",
        responses={200: WalletTransactionSerializer(many=True)}
    )
    def get_queryset(self):
        return WalletTransaction.objects.filter(wallet__user=self.request.user)


class WalletSummaryView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="دریافت خلاصه کیف پول",
        responses={200: WalletSummarySerializer}
    )
    def get(self, request):
        wallet = get_object_or_404(Wallet, user=request.user)
        serializer = WalletSummarySerializer(wallet)
        return self.standard_response(wallet=wallet, data=serializer.data)


class WalletSetPinView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="تنظیم رمز PIN کیف پول",
        request_body=PinSetSerializer,
        responses={200: openapi.Response("PIN ثبت شد")}
    )
    def post(self, request):
        wallet = get_object_or_404(Wallet, user=request.user)
        serializer = PinSetSerializer(data=request.data)
        if serializer.is_valid():
            pin_code = serializer.validated_data['pin_code']
            expiry_days = serializer.validated_data.get('expiry_days', 30)
            try:
                with transaction.atomic():
                    wallet.set_pin_code(pin_code, expiry_days=expiry_days)
                    WalletOperationLog.objects.create(
                        wallet=wallet,
                        operation_type='pin_set',
                        status='success',
                        message='PIN کیف پول با موفقیت تنظیم شد.'
                    )
                return self.standard_response(message="رمز PIN با موفقیت تنظیم شد.", wallet=wallet)
            except ValidationError as e:
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='pin_set',
                    status='failure',
                    message=str(e)
                )
                return self.standard_response(success=False, message=str(e), wallet=wallet, status_code=400)
        return self.standard_response(success=False, message="داده‌های ورودی نامعتبر است.", errors=serializer.errors, status_code=400)


class WalletVerifyPinView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="تأیید رمز PIN کیف پول",
        request_body=PinVerifySerializer,
        responses={200: openapi.Response("PIN صحیح است")}
    )
    def post(self, request):
        wallet = get_object_or_404(Wallet, user=request.user)
        serializer = PinVerifySerializer(data=request.data)
        if serializer.is_valid():
            pin_code = serializer.validated_data['pin_code']
            if wallet.check_pin_code(pin_code):
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='pin_verify',
                    status='success',
                    message='رمز PIN با موفقیت تأیید شد.'
                )
                return self.standard_response(message="رمز PIN صحیح است.", wallet=wallet)
            else:
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='pin_verify',
                    status='failure',
                    message='رمز PIN اشتباه یا قفل موقت فعال است.'
                )
                return self.standard_response(success=False, message="رمز PIN اشتباه است یا حساب به دلیل تلاش‌های زیاد قفل شده است.", wallet=wallet, status_code=403)
        return self.standard_response(success=False, message="داده‌های ورودی نامعتبر است.", errors=serializer.errors, status_code=400)


class WalletDepositView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="واریز وجه به کیف پول",
        request_body=WalletDepositSerializer,
        responses={
            200: openapi.Response("واریز موفق"),
            400: openapi.Response("خطا در داده‌ها یا اعتبارسنجی")
        }
    )
    def post(self, request):
        serializer = WalletDepositSerializer(data=request.data)
        if not serializer.is_valid():
            return self.error_response(
                message="داده‌های ورودی نامعتبر است.",
                errors=serializer.errors
            )

        wallet = get_object_or_404(Wallet, user=request.user)
        amount = serializer.validated_data["amount"]
        description = serializer.validated_data.get("description", "")

        try:
            previous_balance = wallet.balance
            wallet.balance += amount
            wallet.save(update_fields=["balance"])

            WalletTransaction.objects.create(
                wallet=wallet,
                transaction_type=TransactionType.DEPOSIT,
                amount=amount,
                previous_balance=previous_balance,
                status="completed",
                description=description or "واریز مستقیم",
                source="manual",
                from_user=None,
                to_user=wallet.user,
            )

            WalletOperationLog.objects.create(
                wallet=wallet,
                operation_type=TransactionType.DEPOSIT,
                amount=amount,
                status=OperationStatus.SUCCESS,
                message="واریز موفق دستی",
                metadata={"method": "WalletDepositView"}
            )

            return self.success_response(
                message="واریز با موفقیت انجام شد.",
                wallet=wallet,
                data={"balance": wallet.balance}
            )

        except ValidationError as e:
            return self.error_response(
                message=str(e),
                wallet=wallet
            )


class WalletWithdrawView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="برداشت وجه از کیف پول",
        request_body=DepositWithdrawSerializer,
        responses={
            200: openapi.Response("برداشت موفق"),
            400: openapi.Response("خطا در اعتبارسنجی یا محدودیت برداشت")
        }
    )
    def post(self, request):
        wallet = get_object_or_404(Wallet, user=request.user)
        serializer = DepositWithdrawSerializer(data=request.data)
        if serializer.is_valid():
            amount = serializer.validated_data['amount']
            description = serializer.validated_data.get('description', '')
            try:
                wallet.withdraw(amount, description=description)
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='withdraw',
                    amount=amount,
                    status='success',
                    message='برداشت با موفقیت انجام شد.'
                )
                return self.standard_response(message="برداشت با موفقیت انجام شد.", wallet=wallet)
            except ValidationError as e:
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='withdraw',
                    amount=amount,
                    status='failure',
                    message=str(e)
                )
                return self.standard_response(success=False, message=str(e), wallet=wallet, status_code=400)
        return self.standard_response(success=False, message="داده‌های ورودی نامعتبر است.", errors=serializer.errors, status_code=400)


class WalletTransferView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="انتقال وجه به کیف پول دیگر",
        request_body=TransferSerializer,
        responses={
            200: openapi.Response("انتقال موفق"),
            400: openapi.Response("خطا در اعتبارسنجی یا موجودی"),
            404: openapi.Response("کیف پول گیرنده یافت نشد")
        }
    )
    def post(self, request):
        wallet = get_object_or_404(Wallet, user=request.user)
        serializer = TransferSerializer(data=request.data)
        if serializer.is_valid():
            to_user_id = serializer.validated_data['to_user_id']
            amount = serializer.validated_data['amount']
            description = serializer.validated_data.get('description', '')

            to_wallet = Wallet.objects.filter(user_id=to_user_id).first()
            if not to_wallet:
                return self.standard_response(success=False, message="کیف پول گیرنده پیدا نشد.", status_code=404)

            try:
                with transaction.atomic():
                    wallet.transfer_to(to_wallet, amount, description)
                    WalletOperationLog.objects.create(
                        wallet=wallet,
                        operation_type='transfer',
                        amount=amount,
                        status='success',
                        message=f'انتقال به {to_wallet.user} انجام شد.'
                    )
                return self.standard_response(message="انتقال با موفقیت انجام شد.", wallet=wallet)
            except ValidationError as e:
                WalletOperationLog.objects.create(
                    wallet=wallet,
                    operation_type='transfer',
                    amount=amount,
                    status='failure',
                    message=str(e)
                )
                return self.standard_response(success=False, message=str(e), wallet=wallet, status_code=400)
        return self.standard_response(success=False, message="داده‌های ورودی نامعتبر است.", errors=serializer.errors, status_code=400)


class WalletStatsView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="آمار کلی کیف پول",
        responses={200: WalletStatsSerializer}
    )
    def get(self, request):
        wallet = request.user.wallet

        transactions = WalletTransaction.objects.filter(wallet=wallet)

        total_deposit = transactions.filter(
            transaction_type='deposit').aggregate(Sum('amount'))['amount__sum'] or 0
        total_withdraw = transactions.filter(
            transaction_type='withdraw').aggregate(Sum('amount'))['amount__sum'] or 0

        serializer = WalletStatsSerializer({
            "balance": wallet.balance,
            "total_deposit": total_deposit,
            "total_withdraw": total_withdraw,
            "total_transactions": transactions.count()
        })

        return self.standard_response(data=serializer.data, wallet=wallet)


class WalletAnalyticsView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="گزارش آنالیتیکس کیف پول",
        operation_description="نمایش خلاصه تراکنش‌های کیف پول در بازه زمانی مشخص (مثلاً ۷ روز گذشته)",
        manual_parameters=[
            openapi.Parameter(
                "days", openapi.IN_QUERY, description="تعداد روزهای گذشته برای آنالیز", type=openapi.TYPE_INTEGER, default=7
            )
        ],
        responses={
            200: openapi.Response(
                description="گزارش موفقیت‌آمیز",
                schema=WalletAnalyticsSerializer(many=True)
            )
        }
    )
    def get(self, request):
        wallet = request.user.wallet
        since_days = int(request.query_params.get("days", 7))
        since_date = timezone.now().date() - timedelta(days=since_days)

        queryset = WalletTransaction.objects.filter(
            wallet=wallet,
            created_at__date__gte=since_date
        ).annotate(date=TruncDate('created_at')).values('date', 'transaction_type').annotate(
            total=Sum('amount')
        )

        analytics_map = {}
        for entry in queryset:
            date = entry["date"]
            t_type = entry["transaction_type"]
            amount = entry["total"]

            if date not in analytics_map:
                analytics_map[date] = {
                    "deposit": 0,
                    "withdraw": 0,
                    "transfer": 0
                }

            if t_type in analytics_map[date]:
                analytics_map[date][t_type] = amount

        result = []
        for date, values in sorted(analytics_map.items()):
            result.append({
                "date": date,
                "deposit": values.get("deposit", 0),
                "withdraw": values.get("withdraw", 0),
                "transfer": values.get("transfer", 0)
            })

        serializer = WalletAnalyticsSerializer(result, many=True)
        return self.standard_response(data=serializer.data, wallet=wallet)

# مدیریت ادمین


class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_superuser


class AdminWalletListView(WalletResponseMixin, generics.ListAPIView):
    queryset = Wallet.objects.select_related("user").all()
    serializer_class = AdminWalletSerializer
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="لیست کیف پول‌های همه کاربران (ادمین)",
        responses={
            200: openapi.Response(
                description="لیست کیف پول‌ها",
                schema=AdminWalletSerializer(many=True)
            ),
            403: "دسترسی غیرمجاز"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class AdminWalletDetailView(WalletResponseMixin, generics.RetrieveAPIView):
    queryset = Wallet.objects.select_related("user").all()
    serializer_class = AdminWalletSerializer
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="جزئیات کیف پول یک کاربر (ادمین)",
        responses={
            200: openapi.Response(
                description="جزئیات کیف پول",
                schema=AdminWalletSerializer()
            ),
            404: "کیف پول یافت نشد",
            403: "دسترسی غیرمجاز"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class AdminWalletAdjustBalanceView(WalletResponseMixin, APIView):
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="اصلاح موجودی کیف پول به صورت دستی توسط ادمین",
        request_body=AdminAdjustBalanceSerializer,
        responses={
            200: openapi.Response(
                description="اصلاح موجودی موفقیت‌آمیز",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "موجودی با موفقیت اصلاح شد.",
                        "data": {
                            "wallet": {
                                "balance": 500000,
                                "updated_at": "2025-07-25T12:00:00Z"
                            }
                        }
                    }
                }
            ),
            400: "داده نامعتبر یا موجودی منفی مجاز نیست",
            403: "دسترسی غیرمجاز",
            404: "کیف پول یافت نشد"
        }
    )
    def post(self, request, pk):
        wallet = get_object_or_404(Wallet, pk=pk)

        serializer = AdminAdjustBalanceSerializer(data=request.data)
        if not serializer.is_valid():
            return self.error_response(message="داده نامعتبر", errors=serializer.errors)

        data = serializer.validated_data
        amount = data["amount"]
        operation = data["operation"]
        description = data["description"]

        previous = wallet.balance
        new_balance = previous + amount if operation == "increase" else previous - amount

        if new_balance < 0:
            return self.error_response(message="موجودی منفی مجاز نیست.")

        wallet.balance = new_balance
        wallet.save(update_fields=["balance"])

        WalletTransaction.objects.create(
            wallet=wallet,
            transaction_type=TransactionType.OTHER,
            amount=amount if operation == "increase" else -amount,
            previous_balance=previous,
            status="completed",
            description=f"اصلاح دستی: {description}",
            source="admin_manual",
            from_user=None,
            to_user=wallet.user,
        )

        WalletOperationLog.objects.create(
            wallet=wallet,
            operation_type=TransactionType.OTHER,
            amount=amount,
            status=OperationStatus.SUCCESS,
            message=f"اصلاح توسط ادمین: {description}",
            metadata={"admin_id": request.user.id, "operation": operation}
        )

        return self.success_response(
            message="موجودی با موفقیت اصلاح شد.",
            wallet=wallet,
        )


class AdminTransactionListView(WalletResponseMixin, generics.ListAPIView):
    queryset = WalletTransaction.objects.select_related(
        "wallet", "wallet__user").all()
    serializer_class = AdminTransactionSerializer
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="لیست تراکنش‌های کیف پول‌ها (ادمین)",
        responses={
            200: openapi.Response(
                description="لیست تراکنش‌ها",
                schema=AdminTransactionSerializer(many=True)
            ),
            403: "دسترسی غیرمجاز"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class AdminTransactionDetailView(WalletResponseMixin, generics.RetrieveAPIView):
    queryset = WalletTransaction.objects.select_related(
        "wallet", "wallet__user").all()
    serializer_class = AdminTransactionSerializer
    permission_classes = [IsSuperAdmin]

    @swagger_auto_schema(
        operation_summary="جزئیات یک تراکنش کیف پول (ادمین)",
        responses={
            200: openapi.Response(
                description="جزئیات تراکنش",
                schema=AdminTransactionSerializer()
            ),
            404: "تراکنش یافت نشد",
            403: "دسترسی غیرمجاز"
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class ZarinpalPaymentInitiateView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="شروع فرآیند پرداخت از طریق زرین پال",
        request_body=ZarinpalPaymentInitiateSerializer,
        responses={
            200: openapi.Response(
                description="لینک پرداخت ایجاد شد",
                examples={
                    "application/json": {
                          "success": True,
                          "message": "لینک پرداخت ساخته شد",
                            "data": {
                                "payment_url": "https://www.zarinpal.com/startpay/AuthorityCode",
                                "payment_id": "uuid-of-payment"
                            }
                    }
                }
            ),
            400: "داده نامعتبر یا خطا در تنظیمات درگاه",
            403: "دسترسی غیرمجاز"
        }
    )
    def post(self, request):
        serializer = ZarinpalPaymentInitiateSerializer(data=request.data)
        if not serializer.is_valid():
            return self.error_response(message="داده نامعتبر", errors=serializer.errors)

        amount = serializer.validated_data['amount']
        description = serializer.validated_data.get('description', '')

        wallet = get_object_or_404(Wallet, user=request.user)

        payment = ZarinPayment.objects.create(
            wallet=wallet,
            amount=amount,
            description=description,
            status=ZarinPayment.PaymentStatus.PENDING,
        )

        merchant_id = getattr(settings, "ZARINPAL_MERCHANT_ID", None)
        if not merchant_id:
            return self.error_response(message="تنظیمات درگاه پرداخت ناقص است.")

        callback_url = request.build_absolute_uri(
            f"/wallet/external/verify-payment/?payment_id={payment.id}"
        )

        data = {
            "merchant_id": merchant_id,
            "amount": int(amount),  # زرین پال مبلغ باید int باشه
            "callback_url": callback_url,
            "description": description,
        }

        try:
            response = requests.post(
                settings.ZARINPAL_REQUEST_URL, json=data, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            return self.error_response(message=f"خطا در ارتباط با درگاه پرداخت: {str(e)}")

        result = response.json()

        if result.get('data', {}).get('code') == 100:
            authority = result['data']['authority']
            payment.authority = authority
            payment.payment_url = settings.ZARINPAL_STARTPAY_URL.format(
                authority)
            payment.save(update_fields=['authority', 'payment_url'])

            return self.success_response(
                message="لینک پرداخت ساخته شد",
                data={"payment_url": payment.payment_url,
                      "payment_id": str(payment.id)}
            )
        else:
            err = result.get('errors', {}).get(
                'message', 'خطا در درگاه پرداخت')
            return self.error_response(message=f"خطا در درگاه: {err}")


class ZarinpalPaymentVerifyView(WalletResponseMixin, APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="تأیید پرداخت زرین پال",
        manual_parameters=[
            openapi.Parameter(
                'payment_id', openapi.IN_QUERY, description="شناسه پرداخت", type=openapi.TYPE_STRING, required=True
            ),
            openapi.Parameter(
                'Authority', openapi.IN_QUERY, description="کد اعتبار پرداخت", type=openapi.TYPE_STRING, required=True
            ),
        ],
        responses={
            200: openapi.Response(
                description="پرداخت تأیید شد",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "پرداخت با موفقیت تأیید شد.",
                            "data": {
                                "wallet": {
                                    "balance": 1000000,
                                    "updated_at": "2025-07-25T12:00:00Z"
                                }
                            }
                    }
                }
            ),
            400: "پارامترهای نامعتبر",
            403: "دسترسی غیرمجاز",
            404: "پرداخت یافت نشد"
        }
    )
    def get(self, request):
        serializer = ZarinpalVerifyQuerySerializer(data=request.query_params)
        if not serializer.is_valid():
            return self.error_response(message="پارامترهای نامعتبر", errors=serializer.errors)

        validated = serializer.validated_data
        payment_id = validated["payment_id"]
        authority = validated["Authority"]

        # پیدا کردن پرداخت
        payment = get_object_or_404(
            ZarinPayment, id=payment_id, authority=authority)

        if payment.is_success():
            return self.success_response(message="پرداخت قبلاً تایید شده است.")

        # تنظیمات درگاه
        merchant_id = getattr(settings, "ZARINPAL_MERCHANT_ID", None)
        if not merchant_id:
            return self.error_response(message="تنظیمات درگاه پرداخت ناقص است.")

        verify_data = {
            "merchant_id": merchant_id,
            "amount": int(payment.amount),
            "authority": authority,
        }

        try:
            verify_response = requests.post(
                settings.ZARINPAL_VERIFY_URL, json=verify_data, timeout=10)
            verify_response.raise_for_status()
        except requests.RequestException as e:
            return self.error_response(message=f"خطا در ارتباط با درگاه پرداخت: {str(e)}")

        verify_result = verify_response.json()
        code = verify_result.get("data", {}).get("code")

        if code == 100:
            # تایید موفقیت‌آمیز
            payment.status = ZarinPayment.PaymentStatus.SUCCESS
            payment.callback_data = dict(request.query_params)
            payment.updated_at = timezone.now()
            payment.save(update_fields=[
                         "status", "callback_data", "updated_at"])

            wallet = payment.wallet
            previous_balance = wallet.balance
            wallet.balance += payment.amount
            wallet.save(update_fields=["balance"])

            WalletTransaction.objects.create(
                wallet=wallet,
                transaction_type=TransactionType.DEPOSIT,
                amount=payment.amount,
                previous_balance=previous_balance,
                status="completed",
                description=f"واریز از طریق زرین پال، کد: {authority}",
                source="zarinpal",
                from_user=None,
                to_user=wallet.user,
            )

            WalletOperationLog.objects.create(
                wallet=wallet,
                operation_type=TransactionType.DEPOSIT,
                amount=payment.amount,
                status=OperationStatus.SUCCESS,
                message=f"واریز موفق از زرین پال",
                metadata={"payment_id": str(
                    payment.id), "authority": authority},
            )

            return self.success_response(message="پرداخت با موفقیت تأیید شد.", wallet=wallet)

        else:
            # خطا از سمت زرین‌پال
            err_msg = verify_result.get("errors", {}).get(
                "message", "خطا در تایید پرداخت")
            payment.status = ZarinPayment.PaymentStatus.FAILED
            payment.callback_data = dict(request.query_params)
            payment.updated_at = timezone.now()
            payment.save(update_fields=[
                         "status", "callback_data", "updated_at"])

            return self.error_response(message=f"تأیید پرداخت ناموفق بود: {err_msg}")


class WithdrawRequestDetailView(WalletResponseMixin, generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WithdrawRequestSerializer

    def get_queryset(self):
        # فقط درخواست‌های کاربر جاری را برگرداند
        return WithdrawRequest.objects.filter(wallet__user=self.request.user)

    @swagger_auto_schema(
        operation_summary="مشاهده جزئیات یک درخواست برداشت",
        responses={200: WithdrawRequestSerializer}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class WithdrawRequestCancelView(WalletResponseMixin, generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    # یا اگر سریالایزر خاص لغو داری استفاده کن
    serializer_class = WithdrawRequestSerializer
    http_method_names = ['patch']

    def get_queryset(self):
        # فقط درخواست‌های خود کاربر را اجازه ویرایش بده
        return WithdrawRequest.objects.filter(wallet__user=self.request.user, status=WithdrawRequestStatus.PENDING)

    @swagger_auto_schema(
        operation_summary="لغو درخواست برداشت توسط کاربر",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "status": openapi.Schema(type=openapi.TYPE_STRING, enum=[WithdrawRequestStatus.CANCELED]),
            },
            required=["status"],
        ),
        responses={
            200: openapi.Response("درخواست لغو شد"),
            400: "درخواست معتبر نیست یا لغو امکان‌پذیر نیست"
        }
    )
    def patch(self, request, *args, **kwargs):
        # فقط اجازه تغییر وضعیت به لغو شده را بدهیم
        if request.data.get("status") != WithdrawRequestStatus.CANCELED:
            return self.error_response(message="فقط تغییر وضعیت به لغو مجاز است.", status_code=400)

        return super().partial_update(request, *args, **kwargs)
