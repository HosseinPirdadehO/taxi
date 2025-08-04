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
    ParentListView,
    StudentRetrieveUpdateView,
    DriverRetrieveUpdateView,
    ParentRetrieveUpdateView,
    CurrentStudentProfileView,
    CurrentDriverProfileView,
    CurrentParentProfileView,
    LocationListCreateView,
    LocationRetrieveUpdateDestroyView,
    CurrentUserLocationView,
    OverviewReportView,
    RoleCountReportView,
    ReferralReportView,
    ActiveUsersReportView,
    NewUsersReportView,
    LocationStatsReportView,
    CheckPhoneNumberView

)
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

urlpatterns = [
    path('check-phone/', CheckPhoneNumberView.as_view(), name='check-phone'),
    # OTP Authentication
    # ارسال کد تایید به شماره موبایل
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    # بررسی کد تایید و ورود/ثبت‌نام
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(),
         name='resend-otp'),  # ارسال مجدد کد تایید

    # JWT Token Authentication
    path('token/', TokenObtainPairView.as_view(),
         name='token_obtain_pair'),  # گرفتن توکن دسترسی و رفرش
    path('test-token/', TestTokenView.as_view(),
         name='test-token'),  # تست اعتبار توکن
    path('refresh-token/', TokenRefreshView.as_view(),
         name='token_refresh'),  # تازه‌سازی توکن دسترسی

    # خروج از سیستم
    # خروج کاربر و بلاک کردن توکن
    path('logout/', LogoutView.as_view(), name='auth_logout'),

    # تغییر شماره موبایل
    path('change-phone/request/', ChangePhoneRequestView.as_view(),
         name='change_phone_request'),  # درخواست تغییر شماره
    path('change-phone/verify/', ChangePhoneVerifyView.as_view(),
         name='change_phone_verify'),  # تایید تغییر شماره

    # مدیریت رمزعبور
    path('set-password/', SetPasswordView.as_view(),
         name='set-password'),  # تنظیم یا تغییر رمز عبور
    path('reset-password/', PasswordResetView.as_view(),
         name='reset-password'),  # بازیابی رمز عبور

    # تکمیل پروفایل پس از ثبت‌نام یا ورود
    path('complete-profile/', CompleteProfileView.as_view(),
         name='complete-profile'),

    # مشاهده اطلاعات کاربر فعلی
    path('me/', UserMeView.as_view(), name='user-me'),

    # مشاهده و ویرایش پروفایل کاربر با شناسه
    path('users/<uuid:pk>/', UserRetrieveUpdateView.as_view(), name='user-detail'),

    # بخش رفرال
    path('referral/', RegisterUserWithReferralView.as_view(),
         name='register-with-referral'),  # ثبت‌نام با کد معرف
    # لیست کاربران معرفی شده توسط خود کاربر
    path('referrals/mine/', MyReferralsView.as_view(), name='referral-mine'),
    path('referrals/inviter/', MyInviterView.as_view(),
         name='referral-inviter'),  # مشاهده معرف خود کاربر
    path('referrals/stats/', ReferralStatsView.as_view(),
         name='referral-stats'),  # آمار رفرال

    # لیست کاربران بر اساس نقش‌ها
    path('users/', UserListView.as_view(),
         name='user-list'),  # لیست کلی کاربران
    path('schools/', SchoolListView.as_view(),
         name='school-list'),  # لیست مدارس
    path('drivers/', DriverListView.as_view(),
         name='driver-list'),  # لیست رانندگان
    path('student/', StudentListView.as_view(),
         name='student-list'),  # لیست دانش‌آموزان
    path('parents/', ParentListView.as_view(),
         name='parent-list'),  # لیست والدین
    path('transport-admins/', TransportAdminListView.as_view(),
         name='transport-admin-list'),  # لیست ادمین‌های ترابری
    path('education-admins/', EducationAdminListView.as_view(),
         name='education-admin-list'),  # لیست ادمین‌های آموزشی
    path('super-admins/', SuperAdminListView.as_view(),
         name='super-admin-list'),  # لیست سوپرادمین‌ها

    # جزئیات و ویرایش پروفایل هر نقش با شناسه
    path('student/<uuid:pk>/', StudentRetrieveUpdateView.as_view(),
         name='student-detail'),  # دانش‌آموز
    path('drivers/<uuid:pk>/', DriverRetrieveUpdateView.as_view(),
         name='driver-detail'),  # راننده
    path('parents/<uuid:pk>/', ParentRetrieveUpdateView.as_view(),
         name='parent-detail'),  # والدین

    # پروفایل کاربر فعلی برای هر نقش
    path('me/student/', CurrentStudentProfileView.as_view(),
         name='me-student'),  # پروفایل دانش‌آموز فعلی
    path('me/driver/', CurrentDriverProfileView.as_view(),
         name='me-driver'),  # پروفایل راننده فعلی
    path('me/parent/', CurrentParentProfileView.as_view(),
         name='me-parent'),  # پروفایل والد فعلی

    path('locations/', LocationListCreateView.as_view(),
         name='location-list-create'),
    path('locations/<int:pk>/',
         LocationRetrieveUpdateDestroyView.as_view(), name='location-detail'),
    # مسیر نمونه برای مکان کاربر فعلی (در صورت نیاز)
    path('me/location/', CurrentUserLocationView.as_view(), name='me-location'),
    # گزارش گیری و آمار های کلی
    path('reports/overview/', OverviewReportView.as_view(), name='report-overview'),
    path('reports/users/roles/', RoleCountReportView.as_view(), name='report-roles'),
    path('reports/referrals/', ReferralReportView.as_view(),
         name='report-referrals'),
    path('reports/active-users/', ActiveUsersReportView.as_view(),
         name='report-active-users'),
    path('reports/new-users/', NewUsersReportView.as_view(),
         name='report-new-users'),
    path('reports/locations/', LocationStatsReportView.as_view(),
         name='report-locations'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL,
                          document_root=settings.STATIC_ROOT)

# git add .
# git commit -m 'june4'
# git branch -M main
# git push -u origin main


# مسیرهای مخصوص کاربران عادی (Self-service APIs)
    # •	send-otp/ — ارسال کد تایید (ثبت‌نام / ورود)
    # •	verify-otp/ — تایید کد OTP و ورود
    # •	resend-otp/ — ارسال مجدد کد تایید
    # •	token/ — دریافت توکن JWT (ورود)
    # •	refresh-token/ — تازه‌سازی توکن
    # •	test-token/ — تست اعتبار توکن
    # •	logout/ — خروج و بلاک کردن توکن
    # •	change-phone/request/ — درخواست تغییر شماره موبایل
    # •	change-phone/verify/ — تایید تغییر شماره
    # •	set-password/ — تنظیم یا تغییر رمز عبور
    # •	reset-password/ — بازیابی رمز عبور
    # •	complete-profile/ — تکمیل یا ویرایش پروفایل خود
    # •	me/ — مشاهده اطلاعات پروفایل خود
    # •	me/student/ — مشاهده و ویرایش پروفایل دانش‌آموز خود
    # •	me/driver/ — مشاهده و ویرایش پروفایل راننده خود
    # •	me/parent/ — مشاهده و ویرایش پروفایل والد خود
    # •	me/location/ — مشاهده مکان مرتبط با خود
    # •	referrals/mine/ — لیست کسانی که خود کاربر دعوت کرده
    # •	referrals/inviter/ — مشاهده معرف خود کاربر


# مسیرهای مخصوص ادمین‌ها (مدیریت و نظارت)
# 	•	users/ — لیست کل کاربران (فیلتر و جستجو)
# 	•	users/<uuid:pk>/ — مشاهده و ویرایش کاربران خاص
# 	•	schools/ — لیست مدارس
# 	•	drivers/ — لیست رانندگان
# 	•	student/ — لیست دانش‌آموزان
# 	•	parents/ — لیست والدین
# 	•	transport-admins/ — لیست ادمین‌های ترابری
# 	•	education-admins/ — لیست ادمین‌های آموزشی
# 	•	super-admins/ — لیست سوپرادمین‌ها
# 	•	student/<uuid:pk>/ — مشاهده و ویرایش پروفایل دانش‌آموز خاص
# 	•	drivers/<uuid:pk>/ — مشاهده و ویرایش پروفایل راننده خاص
# 	•	parents/<uuid:pk>/ — مشاهده و ویرایش پروفایل والد خاص
# 	•	referral/ — ثبت‌نام با کد معرف (می‌تواند برای هر دو باشد، اما معمولا کاربر عادی استفاده می‌کند)
# 	•	گزارش‌ها و آمارها (عمدتا ادمین‌ها):
# 	•	reports/overview/
# 	•	reports/users/roles/
# 	•	reports/referrals/
# 	•	reports/active-users/
# 	•	reports/new-users/
# 	•	reports/locations/
# 	•	locations/ — مدیریت کامل مکان‌ها (CRUD) برای ادمین
# 	•	locations/<int:pk>/ — مدیریت مکان خاص


# gunicorn taxi.wsgi
