from rest_framework.response import Response
from rest_framework import status
from .serializers import FullUserProfileSerializer  # یا مسیر مناسب پروژه شما


class StandardResponseMixin:
    def standard_response(self, success=True, data=None, message=None,
                          status_code=None, user=None, errors=None):
        """
     روش پاسخ یکپارچه برای پاسخ‌های موفقیت‌آمیز و خطا.
        """
        if success:
            return self.success_response(message=message, data=data, user=user,
                                         status_code=status_code or status.HTTP_200_OK)
        else:
            return self.error_response(message=message, data=data, errors=errors,
                                       status_code=status_code or status.HTTP_400_BAD_REQUEST)

    def success_response(self, message="عملیات با موفقیت انجام شد.", data=None,
                         status_code=status.HTTP_200_OK, user=None):
        """
       یک پاسخ موفقیت‌آمیز استاندارد را برمی‌گرداند.
        """
        response_data = {
            "success": True,
            "message": message,
            "data": data,
        }

        if user:
            user_data = FullUserProfileSerializer(user).data
            response_data["user"] = user_data

        return Response(response_data, status=status_code)

    def error_response(self, message="خطایی رخ داده است.", data=None, errors=None,
                       status_code=status.HTTP_400_BAD_REQUEST):
        """
       یک پاسخ خطای استاندارد را برمی‌گرداند.
        """
        response_data = {
            "success": False,
            "message": message,
        }
        if data is not None:
            response_data["data"] = data
        if errors is not None:
            response_data["errors"] = errors

        return Response(response_data, status=status_code)
