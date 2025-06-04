"""
API应用URL配置
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

# 暂时注释掉复杂的视图导入，等后续实现设备交互功能时再启用
# from .views import (
#     RegisterView, LoginView, UserInfoView,
#     UserPermissionsView, GroupPermissionsView,
#     UserGroupViewSet, DeviceGroupViewSet, DeviceViewSet,
#     DeviceOverviewView, DeviceDetailView, DeviceHeartbeatView
# )

# 创建DRF路由器
router = DefaultRouter()

# 注册ViewSet路由（暂时注释掉，等实现时再启用）
# router.register(r'user-groups', UserGroupViewSet, basename='usergroup')
# router.register(r'device-groups', DeviceGroupViewSet, basename='devicegroup')
# router.register(r'devices', DeviceViewSet, basename='device')

app_name = 'api'

urlpatterns = [
    # JWT认证端点
    path('auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # 暂时注释掉复杂的API端点，等后续实现时再启用
    # # 用户认证
    # path('auth/register/', RegisterView.as_view(), name='auth-register'),
    # path('auth/login/', LoginView.as_view(), name='auth-login'),
    # path('auth/me/', UserInfoView.as_view(), name='auth-me'),

    # # 权限管理
    # path('permissions/user/<int:user_id>/', UserPermissionsView.as_view(), name='user-permissions'),
    # path('permissions/group/<int:group_id>/', GroupPermissionsView.as_view(), name='group-permissions'),

    # # 设备管理
    # path('devices/overview/', DeviceOverviewView.as_view(), name='device-overview'),
    # path('devices/<int:pk>/detail/', DeviceDetailView.as_view(), name='device-detail'),
    # path('devices/heartbeat/', DeviceHeartbeatView.as_view(), name='device-heartbeat'),

    # DRF路由
    path('', include(router.urls)),
]