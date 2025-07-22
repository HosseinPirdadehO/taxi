from django.urls import path
from taxi import settings
from django.conf.urls.static import static
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
    UserRetrieveUpdateView,
    TestTokenView,
    UserListView,
    SchoolListView,
    DriverListView,
    StudentListView,
    TransportAdminListView,
    EducationAdminListView,
    SuperAdminListView,
)
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    # OTP Auth
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    # JWT Token
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('test-token/', TestTokenView.as_view(), name='test-token'),
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
    path('referral/', RegisterUserWithReferralView.as_view(),
         name='register-with-referral'),
    path('referrals/mine/', MyReferralsView.as_view(), name='referral-mine'),
    path('referrals/inviter/', MyInviterView.as_view(), name='referral-inviter'),
    path('referrals/stats/', ReferralStatsView.as_view(), name='referral-stats'),
    # لیست ها
    path('users/', UserListView.as_view(), name='user-list'),
    path('schools/', SchoolListView.as_view(), name='school-list'),
    path('drivers/', DriverListView.as_view(), name='driver-list'),
    path('student/', StudentListView.as_view(), name='Student-list'),
    path('transport-admins/', TransportAdminListView.as_view(),
         name='transport-admin-list'),
    path('education-admins/', EducationAdminListView.as_view(),
         name='education-admin-list'),
    path('super-admins/', SuperAdminListView.as_view(),
         name='super-admin-list'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATIC_ROOT)

# git add .
# git commit -m 'june4'
# git branch -M main
# git push -u origin main
