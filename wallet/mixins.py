from rest_framework.response import Response
from rest_framework import status
from django.utils.translation import gettext_lazy as _
import time
import uuid


class WalletResponseMixin:
    """
    میکسین استاندارد و پیشرفته برای پاسخ‌های API کیف پول
    """

    def _get_processing_time(self):
        """
        زمان پردازش درخواست به میلی‌ثانیه (اختیاری)
        """
        if hasattr(self, '_start_time'):
            return int((time.time() - self._start_time) * 1000)
        return None

    def initial(self, request, *args, **kwargs):
        """
        ثبت زمان شروع پردازش برای محاسبه زمان پاسخ
        اگر view خودت initial نداره، این متد رو صدا بزن:
        super().initial(request, *args, **kwargs)
        """
        self._start_time = time.time()
        if hasattr(super(), 'initial'):
            super().initial(request, *args, **kwargs)

    def standard_response(
        self,
        *,
        success=True,
        message=None,
        wallet=None,
        user=None,
        data=None,
        errors=None,
        transactions_summary=None,
        meta=None,
        status_code=None,
        extra=None,
        request_id=None,
    ):
        """
        پاسخ استاندارد یکپارچه با پشتیبانی از:
        - wallet: اطلاعات کیف پول
        - user: اطلاعات کاربر
        - transactions_summary: خلاصه تراکنش‌ها
        - meta: اطلاعات متا مثل زمان پردازش، نسخه API و ...
        """

        if not request_id:
            request_id = str(uuid.uuid4())

        if success:
            return self.success_response(
                message=message,
                wallet=wallet,
                user=user,
                data=data,
                transactions_summary=transactions_summary,
                meta=meta,
                status_code=status_code,
                extra=extra,
                request_id=request_id,
            )
        else:
            return self.error_response(
                message=message,
                errors=errors,
                wallet=wallet,
                user=user,
                data=data,
                meta=meta,
                status_code=status_code,
                extra=extra,
                request_id=request_id,
            )

    def success_response(
        self,
        message=None,
        wallet=None,
        user=None,
        data=None,
        transactions_summary=None,
        meta=None,
        status_code=None,
        extra=None,
        request_id=None,
    ):
        response_data = {
            "success": True,
            "message": message or _("عملیات با موفقیت انجام شد."),
            "requestId": request_id,
        }

        if wallet:
            response_data["wallet"] = {
                "balance": str(wallet.balance),
                "currency": wallet.currency,
                "withdrawnToday": str(wallet.withdrawn_today),
                "limit": str(wallet.withdraw_limit_per_day),
                "status": wallet.status,
                "pinCodeSet": bool(wallet.pin_code_hash),
                "pinCodeExpiry": wallet.pin_code_expiry.isoformat() if wallet.pin_code_expiry else None,
                "pinCodeExpiringSoon": wallet.is_pin_code_expiring_soon() if hasattr(wallet, 'is_pin_code_expiring_soon') else None,
                "updatedAt": wallet.updated_at.isoformat() if wallet.updated_at else None,
            }

        if user:
            # فرض می‌کنیم یک serializer برای user داری؛ اگه نداری این قسمت رو متناسب پروژه تغییر بده
            from users.serializers import FullUserProfileSerializer
            response_data["user"] = FullUserProfileSerializer(user).data

        if data:
            response_data["data"] = data

        if transactions_summary:
            response_data["transactionsSummary"] = transactions_summary

        if meta is None:
            meta = {}
        # زمان پردازش را اضافه می‌کنیم اگر قبلا تعیین نشده باشد
        if "processingTimeMs" not in meta:
            pt = self._get_processing_time()
            if pt is not None:
                meta["processingTimeMs"] = pt
        # نسخه API و شناسه درخواست را اضافه می‌کنیم
        meta.setdefault("apiVersion", "1.0")
        response_data["meta"] = meta

        if extra:
            response_data.update(extra)

        return Response(response_data, status=status_code or status.HTTP_200_OK)

    def error_response(
        self,
        message=None,
        errors=None,
        wallet=None,
        user=None,
        data=None,
        meta=None,
        status_code=None,
        extra=None,
        request_id=None,
    ):
        response_data = {
            "success": False,
            "message": message or _("عملیات با خطا مواجه شد."),
            "requestId": request_id,
        }

        if errors:
            response_data["errors"] = errors

        if wallet:
            response_data["wallet"] = {
                "balance": str(wallet.balance),
                "currency": wallet.currency,
                "withdrawnToday": str(wallet.withdrawn_today),
                "limit": str(wallet.withdraw_limit_per_day),
                "status": wallet.status,
                "pinCodeSet": bool(wallet.pin_code_hash),
                "pinCodeExpiry": wallet.pin_code_expiry.isoformat() if wallet.pin_code_expiry else None,
                "pinCodeExpiringSoon": wallet.is_pin_code_expiring_soon() if hasattr(wallet, 'is_pin_code_expiring_soon') else None,
                "updatedAt": wallet.updated_at.isoformat() if wallet.updated_at else None,
            }

        if user:
            from users.serializers import FullUserProfileSerializer
            response_data["user"] = FullUserProfileSerializer(user).data

        if data:
            response_data["data"] = data

        if meta is None:
            meta = {}
        if "processingTimeMs" not in meta:
            pt = self._get_processing_time()
            if pt is not None:
                meta["processingTimeMs"] = pt
        meta.setdefault("apiVersion", "1.0")
        response_data["meta"] = meta

        if extra:
            response_data.update(extra)

        return Response(response_data, status=status_code or status.HTTP_400_BAD_REQUEST)
