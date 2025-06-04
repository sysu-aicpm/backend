# api/admin.py

from django.contrib import admin
from .models import (
    User, # 如果你使用的是自定义User模型且想在admin中管理
    UserGroup,
    Device,
    DeviceGroup,
    DeviceLog,
    DeviceUsageRecord,
    UserDevicePermission,
    GroupDevicePermission
)

# 自定义 Admin 界面的显示
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('name', 'device_identifier', 'device_type', 'status', 'ip_address', 'last_heartbeat')
    list_filter = ('device_type', 'status', 'brand')
    search_fields = ('name', 'device_identifier', 'ip_address')
    readonly_fields = ('last_heartbeat',) # 例如，最后心跳时间通常是只读的

class DeviceGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'device_count')
    search_fields = ('name',)
    filter_horizontal = ('devices',) # 如果设备很多，这个控件比默认的更友好

    def device_count(self, obj):
        return obj.devices.count()
    device_count.short_description = '设备数量'

class UserGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'member_count')
    search_fields = ('name',)
    filter_horizontal = ('members',)

    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = '成员数量'

class UserDevicePermissionAdmin(admin.ModelAdmin):
    list_display = ('user', 'device', 'permission_level')
    list_filter = ('permission_level', 'user', 'device')
    search_fields = ('user__email', 'device__name')

class GroupDevicePermissionAdmin(admin.ModelAdmin):
    list_display = ('user_group', 'get_target_type', 'get_target_name', 'permission_level')
    list_filter = ('permission_level', 'user_group')
    search_fields = ('user_group__name', 'device__name', 'device_group__name')

    def get_target_type(self, obj):
        if obj.device:
            return "设备"
        elif obj.device_group:
            return "设备组"
        return "N/A"
    get_target_type.short_description = '目标类型'

    def get_target_name(self, obj):
        if obj.device:
            return obj.device.name
        elif obj.device_group:
            return obj.device_group.name
        return "N/A"
    get_target_name.short_description = '目标名称'

class DeviceLogAdmin(admin.ModelAdmin):
    list_display = ('device', 'timestamp', 'log_message_short')
    list_filter = ('device', 'timestamp')
    search_fields = ('device__name', 'log_message')
    readonly_fields = ('timestamp',)

    def log_message_short(self, obj):
        return (obj.log_message[:75] + '...') if len(obj.log_message) > 75 else obj.log_message
    log_message_short.short_description = '日志信息'

class DeviceUsageRecordAdmin(admin.ModelAdmin):
    list_display = ('device', 'user_email', 'action', 'timestamp')
    list_filter = ('device', 'action', 'timestamp')
    search_fields = ('device__name', 'user__email', 'action')
    readonly_fields = ('timestamp',)

    def user_email(self, obj):
        return obj.user.email if obj.user else "N/A"
    user_email.short_description = '用户邮箱'


admin.site.register(User)
admin.site.register(UserGroup, UserGroupAdmin)
admin.site.register(Device, DeviceAdmin)
admin.site.register(DeviceGroup, DeviceGroupAdmin)
admin.site.register(DeviceLog, DeviceLogAdmin)
admin.site.register(DeviceUsageRecord, DeviceUsageRecordAdmin)
admin.site.register(UserDevicePermission, UserDevicePermissionAdmin)
admin.site.register(GroupDevicePermission, GroupDevicePermissionAdmin)