# api/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from ..models import (
    Device, DeviceGroup, UserGroup,
    UserDevicePermission, UserDeviceGroupPermission, GroupDevicePermission, PermissionLevel,
    DeviceLog, DeviceUsageRecord
)

User = get_user_model()


# --- Account Serializers ---
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'username')  # username 可以设为和 email 一样或者自动生成
        extra_kwargs = {'username': {'required': False, 'allow_blank': True}}

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("该邮箱已被注册。")
        return value

    def create(self, validated_data):
        # 如果 username 为空，则用 email 填充
        if not validated_data.get('username'):
            validated_data['username'] = validated_data['email']
        user = User.objects.create_user(
            username=validated_data['username'],  # Django User model requires username
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):  # Not a ModelSerializer
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})
    token = serializers.CharField(read_only=True)  # For output

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), username=email, password=password)
            if not user:
                msg = '无法使用提供的凭据登录。'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = '必须同时提供邮箱和密码。'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'is_staff')  # 根据需要添加或移除字段
        read_only_fields = ('id', 'is_staff')


class UserInfoUpdateSerializer(serializers.ModelSerializer):
    # 允许修改昵称 (first_name, last_name), email, password
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True, required=False, style={'input_type': 'password'})
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'last_name')

    def validate_email(self, value):
        # 确保新 email 没有被其他用户使用 (除了当前用户自己)
        user = self.context['request'].user
        if User.objects.filter(email=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("该邮箱已被其他用户注册。")
        return value

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance


# --- Device Serializers ---
class DeviceLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceLog
        fields = ('timestamp', 'log_message')


class DeviceUsageRecordSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True, allow_null=True)

    class Meta:
        model = DeviceUsageRecord
        fields = ('user_email', 'action', 'timestamp', 'parameters')


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = '__all__'
        read_only_fields = ('id', 'status', 'current_power_consumption', 'uptime_seconds', 'last_heartbeat')


class DeviceCreateSerializer(serializers.Serializer):  # 用于添加设备时只接收 ip 和 port
    device_ip = serializers.IPAddressField(required=True)
    device_port = serializers.IntegerField(required=True)


class DeviceInfoUpdateSerializer(serializers.ModelSerializer):  # 用于修改设备信息
    # name = serializers.CharField(required=False)
    # description = serializers.CharField(required=False)
    # brand = serializers.CharField(required=False)
    # ... 其他允许用户修改的字段
    class Meta:
        model = Device
        fields = ('name', 'description', 'brand', 'device_type', 'ip_address', 'port')  # 举例
        # 如果是用 device_info: { "name": "fridge1" } 这种格式，需要自定义 update


class DeviceInfoDictUpdateSerializer(serializers.Serializer):  # 对应你文档中的格式
    device_info = serializers.JSONField(required=True)

    def validate_device_info(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("device_info 必须是一个字典。")
        # 可选：在这里验证 value 字典中允许的键
        allowed_keys = {'name', 'description', 'brand', 'device_type', 'ip_address', 'port'}
        for key in value.keys():
            if key not in allowed_keys:
                raise serializers.ValidationError(f"不支持的键: {key} in device_info.")
        return value


class DeviceOverviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('id', 'name', 'status', 'device_type', 'ip_address', 'port', 'device_identifier')  # 包含网络配置信息


class DeviceDetailSerializer(serializers.ModelSerializer):
    logs = DeviceLogSerializer(many=True, read_only=True)
    usage_records = DeviceUsageRecordSerializer(many=True, read_only=True)

    class Meta:
        model = Device
        fields = (
            'id', 'name', 'device_identifier', 'ip_address', 'port', 'device_type', 'brand',
            'description', 'status', 'current_power_consumption',
            'uptime_seconds', 'last_heartbeat', 'logs', 'usage_records'
        )


class DeviceHeartbeatSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(required=True)
    timestamp = serializers.DateTimeField(required=True)
    status = serializers.ChoiceField(choices=Device.DEVICE_STATUS_CHOICES, required=True)
    data = serializers.JSONField(required=False)  # 包含了功耗、温度等


# --- Device Group Serializers ---
class DeviceGroupSerializer(serializers.ModelSerializer):
    devices_count = serializers.IntegerField(source='devices.count', read_only=True)

    class Meta:
        model = DeviceGroup
        fields = ('id', 'name', 'description', 'devices', 'devices_count')
        extra_kwargs = {
            'devices': {'required': False}  # 创建时不一定立即关联设备
        }


# --- User Group Serializers ---
class UserGroupSerializer(serializers.ModelSerializer):
    members_count = serializers.IntegerField(source='members.count', read_only=True)

    class Meta:
        model = UserGroup
        fields = ('id', 'name', 'description', 'members', 'members_count')
        extra_kwargs = {
            'members': {'required': False}
        }


# --- Permission Serializers ---
class UserDevicePermissionInfoSerializer(serializers.Serializer):  # 用于 GET /permissions/user/{user_id}
    id = serializers.IntegerField(source='device.id')  # 设备/设备组 ID
    type = serializers.SerializerMethodField()  # "device" or "device_group"
    name = serializers.CharField(source='device.name')  # 设备/设备组名
    permission = serializers.CharField(source='permission_level')

    def get_type(self, obj):
        # 这个序列化器目前是基于 UserDevicePermission，所以类型总是 device
        # 如果要混合，需要更复杂的逻辑或不同的序列化器
        return "device"  # 或 "device_group"


class GroupDevicePermissionInfoSerializer(serializers.Serializer):  # GET /permissions/group/{group_id}
    id = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    permission = serializers.CharField(source='permission_level')

    def get_id(self, obj: GroupDevicePermission):
        return obj.device.id if obj.device else obj.device_group.id

    def get_type(self, obj: GroupDevicePermission):
        return "device" if obj.device else "device_group"

    def get_name(self, obj: GroupDevicePermission):
        return obj.device.name if obj.device else obj.device_group.name


class UserPermissionModificationSerializer(serializers.Serializer):
    # user_id 在 URL 中
    # device_id 或 device_group_id, 根据实际情况选择一个
    device_id = serializers.IntegerField(required=False, allow_null=True)
    device_group_id = serializers.IntegerField(required=False, allow_null=True)
    permission_level = serializers.ChoiceField(choices=PermissionLevel.choices, required=True)

    def validate(self, attrs):
        if not attrs.get('device_id') and not attrs.get('device_group_id'):
            raise serializers.ValidationError("必须提供 device_id 或 device_group_id。")
        if attrs.get('device_id') and attrs.get('device_group_id'):
            raise serializers.ValidationError("不能同时提供 device_id 和 device_group_id。")
        return attrs


class GroupPermissionModificationSerializer(serializers.Serializer):  # 和上面类似
    # group_id 在 URL 中
    device_id = serializers.IntegerField(required=False, allow_null=True)
    device_group_id = serializers.IntegerField(required=False, allow_null=True)
    permission_level = serializers.ChoiceField(choices=PermissionLevel.choices, required=True)

    def validate(self, attrs):
        # 同上
        if not attrs.get('device_id') and not attrs.get('device_group_id'):
            raise serializers.ValidationError("必须提供 device_id 或 device_group_id。")
        if attrs.get('device_id') and attrs.get('device_group_id'):
            raise serializers.ValidationError("不能同时提供 device_id 和 device_group_id。")
        return attrs


# --- 设备组权限相关序列化器 ---
class UserDeviceGroupPermissionInfoSerializer(serializers.Serializer):
    """用于 GET /permissions/device-groups/user/{user_id} 的序列化器"""
    id = serializers.IntegerField(source='device_group.id')
    type = serializers.SerializerMethodField()
    name = serializers.CharField(source='device_group.name')
    permission = serializers.CharField(source='permission_level')

    def get_type(self, obj):
        return "device_group"


class UserDeviceGroupPermissionModificationSerializer(serializers.Serializer):
    """用于 PUT /permissions/device-groups/user/{user_id} 的序列化器"""
    device_group_id = serializers.IntegerField(required=True)
    permission_level = serializers.ChoiceField(choices=PermissionLevel.choices, required=True)


class GroupDeviceGroupPermissionInfoSerializer(serializers.Serializer):
    """用于 GET /permissions/device-groups/user-groups/{group_id} 的序列化器"""
    id = serializers.IntegerField(source='device_group.id')
    type = serializers.SerializerMethodField()
    name = serializers.CharField(source='device_group.name')
    permission = serializers.CharField(source='permission_level')

    def get_type(self, obj):
        return "device_group"


class GroupDeviceGroupPermissionModificationSerializer(serializers.Serializer):
    """用于 PUT /permissions/device-groups/user-groups/{group_id} 的序列化器"""
    device_group_id = serializers.IntegerField(required=True)
    permission_level = serializers.ChoiceField(choices=PermissionLevel.choices, required=True)
