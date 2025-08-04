# برای توسعه راحت و آینده‌پذیری:
# 	1.	Swagger / drf-yasg
# 	•	اضافه کردن مستندات API به صورت خودکار
# 	•	تعریف DEFAULT_SCHEMA_CLASS و راه‌اندازی URL مربوطه برای دسترسی به داکیومنتیشن
# 	•	امکان استفاده از داکیومنت‌های زیبا و تعاملی
# 	2.	Celery
# 	•	جدا کردن وظایف زمان‌بر (مثل ارسال پیامک، ایمیل، یا پردازش‌های سنگین) به صف‌های کاری غیرهمزمان
# 	•	اضافه کردن تنظیمات broker (مثلاً Redis) و worker ها
# 	•	تنظیمات مربوط به لود متعادل و مقیاس‌پذیری
# 	3.	Production Settings
# 	•	تغییرات در DEBUG=False و تنظیم ALLOWED_HOSTS
# 	•	استفاده از متغیرهای محیطی برای کلید امنیتی، دیتابیس و سرویس‌ها
# 	•	تنظیمات کش، CDN و سرور فایل استاتیک و مدیا
# 	•	امنیت بیشتر مثل HSTS، CSP، محدود کردن کوکی‌ها و …
# 	4.	Logging حرفه‌ای
# 	•	افزودن لاگرهای فایل، ارسال لاگ به سرویس‌های مانیتورینگ
# 	•	لاگ‌گیری دقیق از خطاها و درخواست‌ها
# 	5.	دستگاه‌های امنیتی و بهینه‌سازی
# 	•	تنظیم Rate Limiting، CSRF، CORS به صورت دقیق‌تر
# 	•	استفاده از SSL/TLS، تنظیمات امنیت HTTP headers

# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻
# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻
# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻
# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻
# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻# ⸻


# ⸻
import pytest
from rest_framework.test import APIClient
from django.urls import reverse
from users.models import PhoneOTP


@pytest.mark.django_db
def test_send_otp_valid_phone():
    client = APIClient()
    url = "/api/auth/send-otp/"  # مسیر کامل درخواست
    response = client.post(url, {"phone_number": "09123456789"})

    assert response.status_code == 200
    assert "detail" in response.data
    assert PhoneOTP.objects.filter(phone_number="09123456789").exists()
