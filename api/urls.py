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

# Import all views for device interaction
from .views.views import (
    RegisterView, UserInfoView, UserListView, CustomTokenRefreshView,
    UserPermissionsView, GroupPermissionsView,
    UserDeviceGroupPermissionsView, GroupDeviceGroupPermissionsView,
    UserGroupViewSet, DeviceGroupViewSet, DeviceViewSet,
    DeviceOverviewView, DeviceDetailView, DeviceHeartbeatView
)

router = DefaultRouter()
# Register ViewSets for device interaction
router.register(r'user-groups', UserGroupViewSet, basename='usergroup')
router.register(r'device-groups', DeviceGroupViewSet, basename='devicegroup')
router.register(r'devices', DeviceViewSet, basename='device')

app_name = 'api'

urlpatterns = [
    # JWT authentication endpoints
    path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # Custom Auth views
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/me/', UserInfoView.as_view(), name='auth-me'),
    path('auth/all/', UserListView.as_view(), name='user-list'),

    # Permissions views
    path('permissions/user/<int:user_id>/', UserPermissionsView.as_view(), name='user-permissions'),
    path('permissions/user-groups/<int:group_id>/', GroupPermissionsView.as_view(), name='group-permissions'), # Assuming group_id is int

    # Device Group Permissions views
    path('permissions/device-groups/user/<int:user_id>/', UserDeviceGroupPermissionsView.as_view(), name='user-device-group-permissions'),
    path('permissions/device-groups/user-groups/<int:group_id>/', GroupDeviceGroupPermissionsView.as_view(), name='group-device-group-permissions'),

    # Device specific views (not part of DeviceViewSet default routes)
    path('devices/overview/', DeviceOverviewView.as_view(), name='device-overview'),
    path('devices/<int:pk>/detail/', DeviceDetailView.as_view(), name='device-detail'), # pk is conventional for detail views
    path('devices/heartbeat/', DeviceHeartbeatView.as_view(), name='device-heartbeat'),

    # DRF router URLs should be included last for ViewSets
    path('', include(router.urls)),
]