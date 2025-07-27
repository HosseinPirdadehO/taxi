from django.urls import path
from wallet.views import (
    WalletDetailView,
    WalletSummaryView,
    WalletSetPinView,
    WalletVerifyPinView,
    WalletDepositView,
    WalletWithdrawView,
    WalletTransferView,
    WalletStatsView,
    WalletAnalyticsView,
    WithdrawRequestCreateView,
    WithdrawRequestListView,
    WithdrawRequestDetailView,
    WithdrawRequestCancelView,
    WithdrawRequestAdminUpdateView,
    WalletTransactionListView,
    AdminWalletListView,
    AdminWalletDetailView,
    AdminWalletAdjustBalanceView,
    AdminTransactionListView,
    AdminTransactionDetailView,
    ZarinpalPaymentInitiateView,
    ZarinpalPaymentVerifyView,
)

urlpatterns = [
    # جزئیات کیف پول کاربر
    path('wallet/', WalletDetailView.as_view(), name='wallet-detail'),
    path('wallet/summary/', WalletSummaryView.as_view(), name='wallet-summary'),

    # عملیات PIN
    path('wallet/pin/set/', WalletSetPinView.as_view(), name='wallet-set-pin'),
    path('wallet/pin/verify/', WalletVerifyPinView.as_view(),
         name='wallet-verify-pin'),

    # عملیات اصلی کیف پول
    path('wallet/deposit/', WalletDepositView.as_view(), name='wallet-deposit'),
    path('wallet/withdraw/', WalletWithdrawView.as_view(), name='wallet-withdraw'),
    path('wallet/transfer/', WalletTransferView.as_view(), name='wallet-transfer'),

    # تراکنش‌ها
    path('wallet/transactions/', WalletTransactionListView.as_view(),
         name='wallet-transaction-list'),

    # درخواست‌های برداشت
    path('wallet/withdraw-requests/', WithdrawRequestListView.as_view(),
         name='withdraw-request-list'),
    path('wallet/withdraw-requests/create/',
         WithdrawRequestCreateView.as_view(), name='withdraw-request-create'),
    path('wallet/withdraw-requests/<uuid:pk>/',
         WithdrawRequestDetailView.as_view(), name='withdraw-request-detail'),
    path('wallet/withdraw-requests/<uuid:pk>/cancel/',
         WithdrawRequestCancelView.as_view(), name='withdraw-request-cancel'),
    path('admin/wallet/withdraw-requests/<uuid:pk>/update/',
         WithdrawRequestAdminUpdateView.as_view(), name='admin-withdraw-request-update'),

    # آنالیتیکس و آمار کیف پول
    path('wallet/stats/', WalletStatsView.as_view(), name='wallet-stats'),
    path('wallet/analytics/', WalletAnalyticsView.as_view(),
         name='wallet-analytics'),

    # مدیریت ادمین کیف پول
    path('admin/wallets/', AdminWalletListView.as_view(), name='admin-wallet-list'),
    path('admin/wallets/<uuid:pk>/', AdminWalletDetailView.as_view(),
         name='admin-wallet-detail'),
    path('admin/wallets/<uuid:pk>/adjust-balance/',
         AdminWalletAdjustBalanceView.as_view(), name='admin-wallet-adjust-balance'),

    path('admin/wallet-transactions/', AdminTransactionListView.as_view(),
         name='admin-transaction-list'),
    path('admin/wallet-transactions/<uuid:pk>/',
         AdminTransactionDetailView.as_view(), name='admin-transaction-detail'),

    # درگاه پرداخت زرین پال
    path('wallet/zarinpal/initiate-payment/',
         ZarinpalPaymentInitiateView.as_view(), name='zarinpal-initiate-payment'),
    path('wallet/zarinpal/verify-payment/',
         ZarinpalPaymentVerifyView.as_view(), name='zarinpal-verify-payment'),
]
#  عملیات اصلی
#  فاز ۲: امنیت و لاگ‌ها
#  فاز ۳: گزارش‌های مالی
#  فاز ۴: اتصال به درگاه بانکی
# فاز ۵: فاکتور، صورتحساب و مالیات (برای B2B)
#  فاز ۶: داشبورد ادمین
