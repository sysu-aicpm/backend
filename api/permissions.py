# api/permissions.py
from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import UserDevicePermission, GroupDevicePermission, PermissionLevel, User


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users (is_staff=True).
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


class CanViewDevice(BasePermission):
    """
    用户对设备至少有 'visible' 权限
    """

    def has_object_permission(self, request, view, obj):  # obj is the Device instance
        if request.user.is_staff:  # 管理员总是有权限
            return True

        # 检查直接用户权限
        user_perm = UserDevicePermission.objects.filter(user=request.user, device=obj).first()
        if user_perm and PermissionLevel.values.index(user_perm.permission_level) >= PermissionLevel.values.index(
                PermissionLevel.VISIBLE):
            return True

        # 检查用户所属组的权限
        user_groups = request.user.custom_user_groups.all()  # 或者 Django 内置的 request.user.groups.all()
        group_perms = GroupDevicePermission.objects.filter(
            user_group__in=user_groups, device=obj
        ).order_by('-permission_level')  # 可以按权限级别排序，取最高的

        if group_perms.exists():
            highest_group_perm = group_perms.first()  # 假设已按级别重要性排序 (需要自定义排序逻辑或比较)
            # A simple way to compare permission levels based on their order in PermissionLevel.choices
            if PermissionLevel.values.index(highest_group_perm.permission_level) >= PermissionLevel.values.index(
                    PermissionLevel.VISIBLE):
                return True
        return False


class CanMonitorDevice(BasePermission):
    """
    用户对设备至少有 'monitorable' 权限
    """

    def has_object_permission(self, request, view, obj):  # obj is the Device instance
        if request.user.is_staff:
            return True

        # 检查直接用户权限
        user_perm = UserDevicePermission.objects.filter(user=request.user, device=obj).first()
        required_level_index = PermissionLevel.values.index(PermissionLevel.MONITORABLE)

        if user_perm and PermissionLevel.values.index(user_perm.permission_level) >= required_level_index:
            return True

        # 检查用户所属组的权限
        user_groups = request.user.custom_user_groups.all()
        group_perms = GroupDevicePermission.objects.filter(user_group__in=user_groups, device=obj)

        for perm in group_perms:
            if PermissionLevel.values.index(perm.permission_level) >= required_level_index:
                return True
        return False


class CanControlDevice(BasePermission):
    """
    用户对设备至少有 'usable' 权限
    """

    def has_object_permission(self, request, view, obj):  # obj is the Device instance
        if request.user.is_staff:
            return True

        user_perm = UserDevicePermission.objects.filter(user=request.user, device=obj).first()
        required_level_index = PermissionLevel.values.index(PermissionLevel.USABLE)

        if user_perm and PermissionLevel.values.index(user_perm.permission_level) >= required_level_index:
            return True

        user_groups = request.user.custom_user_groups.all()
        group_perms = GroupDevicePermission.objects.filter(user_group__in=user_groups, device=obj)

        for perm in group_perms:
            if PermissionLevel.values.index(perm.permission_level) >= required_level_index:
                return True
        return False
