# api/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView  # For JWT

from .views import (
    RegisterView, LoginView, UserInfoView,
    UserPermissionsView, GroupPermissionsView,
    UserGroupViewSet, DeviceGroupViewSet, DeviceViewSet,
    DeviceOverviewView, DeviceDetailView, DeviceHeartbeatView
)

router = DefaultRouter()
router.register(r'user-groups', UserGroupViewSet, basename='usergroup')
router.register(r'device-groups', DeviceGroupViewSet, basename='devicegroup')
router.register(r'devices', DeviceViewSet,
                basename='device')  # Provides list, create, retrieve, update, destroy for devices

# The `basename` is important, especially if your queryset is dynamic or not standard.

app_name = 'api'

urlpatterns = [
    # Auth
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/login/', LoginView.as_view(), name='auth-login'),
    # path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'), # JWT standard login
    # path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # JWT refresh
    path('auth/me/', UserInfoView.as_view(), name='auth-me'),  # "更改" 个人信息 + 查看个人信息

    # Permissions
    path('permissions/user/<int:user_id>/', UserPermissionsView.as_view(), name='user-permissions'),
    path('permissions/group/<int:group_id>/', GroupPermissionsView.as_view(), name='group-permissions'),

    # Devices specific (not covered by ViewSet default actions or custom actions on DeviceViewSet)
    path('devices/overview/', DeviceOverviewView.as_view(), name='device-overview'),
    path('devices/<int:pk>/detail/', DeviceDetailView.as_view(), name='device-detail'),  # pk is device_id
    path('devices/heartbeat/', DeviceHeartbeatView.as_view(), name='device-heartbeat'),

    # Router URLs (for ViewSets)
    path('', include(router.urls)),
]