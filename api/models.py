# api/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, Group as AuthGroup, Permission as AuthPermission # Import with aliases

class User(AbstractUser):
    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    # Add unique related_name arguments to avoid clashes
    groups = models.ManyToManyField(
        AuthGroup, # Use the aliased Group
        verbose_name='groups',
        blank=True,
        help_text=(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="api_user_set", # Changed related_name
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        AuthPermission, # Use the aliased Permission
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="api_user_permissions_set", # Changed related_name
        related_query_name="user",
    )

    def __str__(self):
        return self.email

class UserGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    # Django 的 Group 模型可以用于用户分组，这里我们创建一个新的 UserGroup
    # 如果文档中的 "用户组" 和 Django 的 Group 概念一致，可以考虑直接用 Django Group
    # 或者像这样创建一个新的模型，并通过 ManyToManyField 将 User 和 UserGroup 关联起来
    members = models.ManyToManyField(User, related_name='custom_user_groups', blank=True)
    # created_by = models.ForeignKey(User, related_name='created_user_groups', on_delete=models.SET_NULL, null=True) # 管理员创建

    def __str__(self):
        return self.name

class Device(models.Model):
    DEVICE_STATUS_CHOICES = [
        ('online', '在线'),
        ('offline', '离线'),
        ('error', '故障'),
    ]
    name = models.CharField(max_length=100)
    device_identifier = models.CharField(max_length=100, unique=True, help_text="设备唯一标识，例如 MAC 地址或序列号")
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    port = models.PositiveIntegerField(blank=True, null=True)
    device_type = models.CharField(max_length=50, blank=True, null=True, help_text="例如：空调、冰箱、灯")
    brand = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=DEVICE_STATUS_CHOICES, default='offline')
    current_power_consumption = models.FloatField(blank=True, null=True)
    uptime_seconds = models.PositiveIntegerField(default=0, help_text="运行时间（秒）") # 可以考虑用 DateTimeField 记录上次启动时间
    last_heartbeat = models.DateTimeField(blank=True, null=True)
    # logs 和 usage_records 可以是 TextField 或关联到其他模型
    # logs = models.TextField(blank=True, null=True, help_text="JSON 格式的日志")
    # usage_records = models.TextField(blank=True, null=True, help_text="JSON 格式的使用记录")

    def __str__(self):
        return f"{self.name} ({self.device_identifier})"

class DeviceLog(models.Model): # 更规范的日志记录
    device = models.ForeignKey(Device, related_name='logs', on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    log_message = models.TextField()

    def __str__(self):
        return f"Log for {self.device.name} at {self.timestamp}"

class DeviceUsageRecord(models.Model): # 更规范的使用记录
    device = models.ForeignKey(Device, related_name='usage_records', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True) # 哪个用户操作的
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    parameters = models.JSONField(blank=True, null=True) # 操作参数

    def __str__(self):
        return f"{self.user.email if self.user else 'System'} used {self.device.name}: {self.action}"


class DeviceGroup(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    devices = models.ManyToManyField(Device, related_name='device_groups', blank=True)
    # created_by = models.ForeignKey(User, related_name='created_device_groups', on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.name

class PermissionLevel(models.TextChoices):
    NONE = 'none', '不可见'
    VISIBLE = 'visible', '可见'
    USABLE = 'usable', '可使用'
    CONFIGURABLE = 'configurable', '可配置'
    MONITORABLE = 'monitorable', '可监视'
    MANAGEABLE = 'manageable', '可管理'

# 用户对单个设备的权限
class UserDevicePermission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_permissions')
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='user_permissions')
    # device_group = models.ForeignKey(DeviceGroup, on_delete=models.CASCADE, null=True, blank=True) # 文档中说的是对“设备”的权限，device_group 权限可以通过 UserGroupDevicePermission
    permission_level = models.CharField(max_length=20, choices=PermissionLevel.choices)

    class Meta:
        unique_together = ('user', 'device') # 一个用户对一个设备的权限是唯一的

    def __str__(self):
        return f"{self.user.email} - {self.device.name}: {self.get_permission_level_display()}"

# 用户组对单个设备/设备组的权限
class GroupDevicePermission(models.Model):
    user_group = models.ForeignKey(UserGroup, on_delete=models.CASCADE, related_name='group_device_permissions')
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True, blank=True, related_name='group_permissions')
    device_group = models.ForeignKey(DeviceGroup, on_delete=models.CASCADE, null=True, blank=True, related_name='user_group_permissions')
    permission_level = models.CharField(max_length=20, choices=PermissionLevel.choices)

    class Meta:
        # 一个用户组对一个设备或一个设备组的权限是唯一的 (但不能同时指定 device 和 device_group)
        # 我们可以通过 clean 方法来校验
        unique_together = [
            ('user_group', 'device'),
            ('user_group', 'device_group'),
        ]

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.device and self.device_group:
            raise ValidationError("Cannot assign permission to both a device and a device group simultaneously for a single user group permission entry.")
        if not self.device and not self.device_group:
            raise ValidationError("Must assign permission to either a device or a device group for a user group.")

    def __str__(self):
        target_name = self.device.name if self.device else self.device_group.name
        target_type = "Device" if self.device else "DeviceGroup"
        return f"Group: {self.user_group.name} - {target_type}: {target_name}: {self.get_permission_level_display()}"