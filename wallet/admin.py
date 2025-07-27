from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from .resource import (
    WalletResource,
    WalletTransactionResource,
    WithdrawRequestResource,
    WalletTransferHistoryResource,
    WalletOperationLogResource,
)
from .models import Wallet, WalletTransaction, WithdrawRequest, WalletTransferHistory, WalletOperationLog


@admin.register(Wallet)
class WalletAdmin(ImportExportModelAdmin):
    resource_class = WalletResource
    list_display = ('user', 'balance', 'currency', 'status', 'withdraw_limit_per_day',
                    'withdrawn_today', 'last_withdraw_reset', 'updated_at')
    search_fields = ('user__username', 'user__email')
    list_filter = ('status',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-updated_at',)

    # نمایش لینک به کاربر
    def user(self, obj):
        return obj.user.get_full_name() or obj.user.username
    user.admin_order_field = 'user__username'
    user.short_description = 'کاربر'


@admin.register(WalletTransaction)
class WalletTransactionAdmin(ImportExportModelAdmin):
    resource_class = WalletTransactionResource
    list_display = ('wallet_user', 'transaction_type',
                    'amount', 'status', 'created_at')
    search_fields = ('wallet__user__username', 'description')
    list_filter = ('transaction_type', 'status')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

    def wallet_user(self, obj):
        return obj.wallet.user.get_full_name() or obj.wallet.user.username
    wallet_user.admin_order_field = 'wallet__user__username'
    wallet_user.short_description = 'کاربر'


@admin.register(WithdrawRequest)
class WithdrawRequestAdmin(ImportExportModelAdmin):
    resource_class = WithdrawRequestResource
    list_display = ('wallet_user', 'amount', 'status',
                    'requested_at', 'processed_at')
    search_fields = ('wallet__user__username',)
    list_filter = ('status',)
    readonly_fields = ('requested_at', 'processed_at')
    ordering = ('-requested_at',)

    def wallet_user(self, obj):
        return obj.wallet.user.get_full_name() or obj.wallet.user.username
    wallet_user.admin_order_field = 'wallet__user__username'
    wallet_user.short_description = 'کاربر'


@admin.register(WalletTransferHistory)
class WalletTransferHistoryAdmin(ImportExportModelAdmin):
    resource_class = WalletTransferHistoryResource
    list_display = ('from_user', 'to_user', 'amount', 'created_at')
    search_fields = ('from_wallet__user__username',
                     'to_wallet__user__username')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

    def from_user(self, obj):
        return obj.from_wallet.user.get_full_name() or obj.from_wallet.user.username
    from_user.admin_order_field = 'from_wallet__user__username'
    from_user.short_description = 'ارسال کننده'

    def to_user(self, obj):
        return obj.to_wallet.user.get_full_name() or obj.to_wallet.user.username
    to_user.admin_order_field = 'to_wallet__user__username'
    to_user.short_description = 'دریافت کننده'


@admin.register(WalletOperationLog)
class WalletOperationLogAdmin(ImportExportModelAdmin):
    resource_class = WalletOperationLogResource
    list_display = ('wallet_user', 'operation_type',
                    'amount', 'status', 'created_at')
    search_fields = ('wallet__user__username', 'message')
    list_filter = ('operation_type', 'status')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

    def wallet_user(self, obj):
        return obj.wallet.user.get_full_name() or obj.wallet.user.username
    wallet_user.admin_order_field = 'wallet__user__username'
    wallet_user.short_description = 'کاربر'
