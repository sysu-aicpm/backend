"""
API URL configuration
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

# Comment out complex views for now, will enable when implementing device interaction
# from .views import (
#     RegisterView, LoginView, UserInfoView,
#     UserPermissionsView, GroupPermissionsView,
#     UserGroupViewSet, DeviceGroupViewSet, DeviceViewSet,
#     DeviceOverviewView, DeviceDetailView, DeviceHeartbeatView
# )

router = DefaultRouter()
# Comment out ViewSet registrations for now
# router.register(r'user-groups', UserGroupViewSet, basename='usergroup')
# router.register(r'device-groups', DeviceGroupViewSet, basename='devicegroup')
# router.register(r'devices', DeviceViewSet, basename='device')

app_name = 'api'

urlpatterns = [
    # JWT authentication endpoints
    path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # Comment out complex endpoints for now
    # path('auth/register/', RegisterView.as_view(), name='auth-register'),
    # path('auth/me/', UserInfoView.as_view(), name='auth-me'),
    # path('permissions/user/<int:user_id>/', UserPermissionsView.as_view(), name='user-permissions'),
    # path('devices/overview/', DeviceOverviewView.as_view(), name='device-overview'),

    # DRF router URLs
    path('', include(router.urls)),
]