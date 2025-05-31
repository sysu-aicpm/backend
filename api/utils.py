# api/utils.py
from rest_framework.response import Response
from rest_framework.views import exception_handler
from rest_framework import status


def custom_api_response(success, message, data=None, error_code=None, details=None, status_code=None):
    response_data = {
        "success": success,
        "message": message,
    }
    if data is not None:
        response_data["data"] = data
    if error_code is not None:
        response_data["error_code"] = error_code
    if details is not None:
        response_data["details"] = details

    if status_code is None:
        status_code = status.HTTP_200_OK if success else status.HTTP_400_BAD_REQUEST

    return Response(response_data, status=status_code)


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    if response is not None:
        custom_response_data = {
            "success": False,
            "message": "发生错误",  # Generic message
            "error_code": "GENERIC_ERROR",  # Default error code
            "details": None
        }

        # Try to get more specific error details
        if isinstance(response.data, dict):
            if 'detail' in response.data:
                custom_response_data["message"] = response.data['detail']
                if hasattr(exc, 'get_codes'):
                    codes = exc.get_codes()
                    if isinstance(codes, dict):  # For validation errors
                        first_key = next(iter(codes))
                        custom_response_data["error_code"] = codes[first_key] if isinstance(codes[first_key], str) else \
                        codes[first_key][0]
                        custom_response_data["details"] = response.data  # Keep full validation details
                    else:  # For other errors like NotAuthenticated, PermissionDenied
                        custom_response_data["error_code"] = codes
            elif response.data:  # Handle cases where 'detail' might not be the primary key for error
                first_value = next(iter(response.data.values()))
                if isinstance(first_value, list):
                    custom_response_data["message"] = first_value[0]
                else:
                    custom_response_data["message"] = str(first_value)
                custom_response_data["details"] = response.data

        # Use the custom response format
        return custom_api_response(
            success=False,
            message=custom_response_data["message"],
            error_code=custom_response_data.get("error_code", "UNKNOWN_ERROR"),
            details=custom_response_data.get("details"),
            status_code=response.status_code
        )

    # If response is None, it means Django or some other middleware handled it
    # or it's an unhandled exception. Let Django handle 500 errors.
    return response

# 在 settings.py 中启用自定义异常处理器:
# REST_FRAMEWORK = {
#     ...
#     'EXCEPTION_HANDLER': 'api.utils.custom_exception_handler',
#     ...
# }