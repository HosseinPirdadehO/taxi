from import_export import resources
from .models import Wallet, WalletTransaction, WithdrawRequest, WalletTransferHistory, WalletOperationLog


class WalletResource(resources.ModelResource):
    class Meta:
        model = Wallet
        fields = ('id', 'user__phone_number', 'balance', 'currency', 'status', 'withdraw_limit_per_day',
                  'withdrawn_today', 'last_withdraw_reset', 'created_at', 'updated_at')


class WalletTransactionResource(resources.ModelResource):
    class Meta:
        model = WalletTransaction
        fields = ('id', 'wallet__user__phone_number', 'transaction_type',
                  'amount', 'previous_balance', 'status', 'description', 'created_at')


class WithdrawRequestResource(resources.ModelResource):
    class Meta:
        model = WithdrawRequest
        fields = ('id', 'wallet__user__phone_number', 'amount',
                  'status', 'requested_at', 'processed_at')


class WalletTransferHistoryResource(resources.ModelResource):
    class Meta:
        model = WalletTransferHistory
        fields = ('id', 'from_wallet__user__phone_number',
                  'to_wallet__user__phone_number', 'amount', 'description', 'created_at')


class WalletOperationLogResource(resources.ModelResource):
    class Meta:
        model = WalletOperationLog
        fields = ('id', 'wallet__user__phone_number', 'operation_type',
                  'amount', 'status', 'message', 'created_at')
