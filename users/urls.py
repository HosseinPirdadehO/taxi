from django.urls import path
from users.views.auth_views import (
    SendOTPView,
    UserMeView,
    VerifyOTPView,
    LogoutView,
    ChangePhoneRequestView,
    ChangePhoneVerifyView,
    ResendOTPView,
    SetPasswordView,
    PasswordResetView,
    CompleteProfileView,
    RegisterUserWithReferralView,
    MyInviterView,
    MyReferralsView,
    ReferralStatsView,
    UserRetrieveUpdateView


)
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    # OTP Auth
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    # JWT Token
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh-token/', TokenRefreshView.as_view(), name='token_refresh'),
    # Logout
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    # تغییر شماره موبایل
    path('change-phone/request/', ChangePhoneRequestView.as_view(),
         name='change_phone_request'),
    path('change-phone/verify/', ChangePhoneVerifyView.as_view(),
         name='change_phone_verify'),
    # مدیریت رمزعبور
    path('set-password/', SetPasswordView.as_view(), name='set-password'),
    path('reset-password/', PasswordResetView.as_view(), name='reset-password'),
    # تکمیل پروفایل (پس از ثبت نام یا ورود)
    path('complete-profile/', CompleteProfileView.as_view(),
         name='complete-profile'),
    path('me/', UserMeView.as_view(), name='user-me'),
    # مشاهده، ویرایش کامل و جزئی پروفایل کاربر با شناسه (id)
    path('users/<uuid:pk>/', UserRetrieveUpdateView.as_view(), name='user-detail'),
    # بخش رفرال
    path('Referral/', RegisterUserWithReferralView.as_view(),
         name='register-with-referral'),
    path('referrals/mine/', MyReferralsView.as_view(), name='referral-mine'),
    path('referrals/inviter/', MyInviterView.as_view(), name='referral-inviter'),
    path('referrals/stats/', ReferralStatsView.as_view(), name='referral-stats'),
]


# به سریال ساز های جدید تمام ایتم هارو اصافه کن بعضباشون فقط بوزر عادی
