# api/views.py
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
from django.utils import timezone

from rest_framework import viewsets, status, generics, serializers
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken  # For JWT
# from rest_framework.authtoken.models import Token # For DRF's default token

from ..models import (
    Device, DeviceGroup, UserGroup,
    UserDevicePermission, GroupDevicePermission, PermissionLevel,
    DeviceLog, DeviceUsageRecord
)
from ..serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer, UserInfoUpdateSerializer,
    DeviceSerializer, DeviceCreateSerializer, DeviceInfoUpdateSerializer, DeviceInfoDictUpdateSerializer,
    DeviceOverviewSerializer, DeviceDetailSerializer, DeviceHeartbeatSerializer,
    DeviceGroupSerializer, UserGroupSerializer,
    UserDevicePermissionInfoSerializer, GroupDevicePermissionInfoSerializer,
    UserPermissionModificationSerializer, GroupPermissionModificationSerializer
)
from ..permissions import IsAdminUser, CanViewDevice, CanMonitorDevice, CanControlDevice
from ..utils import custom_api_response

User = get_user_model()


# --- Helper function to get tokens (JWT) ---
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# --- 通用视图 ---
class BaseViewSet(viewsets.ModelViewSet):
    # 你可以在这里添加一些所有 ViewSet 共用的逻辑
    # 例如，覆盖 list, create, retrieve, update, destroy 方法以使用 custom_api_response
    # 但为了简洁，这里暂时不覆盖，除非特别需要

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        Admin users for write operations, authenticated for read.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAdminUser()]
        return [IsAuthenticated()]  # 默认GET操作只需要登录


# --- 账户 (Auth) ---
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]  # 注册允许任何人
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                # 不自动登录，只返回成功信息
                return custom_api_response(True, "注册成功，请登录。")
            except IntegrityError as e:  # 例如，并发情况下 email 重复
                return custom_api_response(False, "注册失败，邮箱可能已被占用。", error_code="REGISTRATION_FAILED",
                                           details=str(e), status_code=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return custom_api_response(False, "注册失败。", error_code="REGISTRATION_ERROR", details=str(e),
                                           status_code=status.HTTP_400_BAD_REQUEST)
        else:
            # serializer.errors 是一个字典，可以提取第一个错误
            first_error_key = next(iter(serializer.errors))
            error_message = serializer.errors[first_error_key][0]
            return custom_api_response(False, f"注册失败: {error_message}", error_code="VALIDATION_ERROR",
                                       details=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

class UserInfoView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return custom_api_response(True, "用户信息获取成功", data=serializer.data)

    def put(self, request, *args, **kwargs):  # 对应你文档中的 "更改"
        user = self.get_object()
        # 使用 UserInfoUpdateSerializer 来处理特定字段的更新
        serializer = UserInfoUpdateSerializer(user, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            # 返回更新后的用户信息，但排除密码等敏感信息
            response_serializer = UserSerializer(user)
            return custom_api_response(True, "个人信息更新成功", data=response_serializer.data)
        return custom_api_response(False, "信息更新失败", error_code="UPDATE_FAILED", details=serializer.errors)


# --- 权限 (Permissions) ---
class UserPermissionsView(APIView):
    permission_classes = [IsAdminUser]  # 只有管理员可以查看/修改用户权限

    def get(self, request, user_id, format=None):
        # 文档说输入 user_email 或 user_id，这里用 user_id
        target_user = get_object_or_404(User, pk=user_id)

        # 获取用户直接权限
        direct_perms = UserDevicePermission.objects.filter(user=target_user)
        direct_perms_data = UserDevicePermissionInfoSerializer(direct_perms, many=True).data

        # 获取用户通过用户组获得的权限 (这部分比较复杂，需要合并和去重)
        # 为简化，这里仅返回直接分配给用户的设备权限。
        # 如果需要包含组权限，需要遍历用户的所有组，再遍历组的所有设备权限，然后合并。
        # 你的文档似乎是指用户对【所有设备】的权限，所以这里列出用户有直接权限的设备。

        # 构建你期望的输出格式
        # { "类型": "device", "名": "device_name", "权限": "level" }
        # UserDevicePermissionInfoSerializer 已经处理了这个格式

        return custom_api_response(True, f"用户 {target_user.email} 的设备权限获取成功", data=direct_perms_data)

    def put(self, request, user_id, format=None):
        target_user = get_object_or_404(User, pk=user_id)
        serializer = UserPermissionModificationSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            device_id = data.get('device_id')
            # device_group_id = data.get('device_group_id') # 当前 UserDevicePermission 不支持 group
            permission_level = data['permission_level']

            if device_id:
                device = get_object_or_404(Device, pk=device_id)
                permission, created = UserDevicePermission.objects.update_or_create(
                    user=target_user,
                    device=device,
                    defaults={'permission_level': permission_level}
                )
                msg = "用户对设备的权限已更新。" if not created else "用户对设备的权限已创建。"
                return custom_api_response(True, msg)
            # elif device_group_id:
            # Handle device group permission for user - not directly supported by UserDevicePermission
            # return custom_api_response(False, "直接为用户分配设备组权限的功能暂未实现，请通过用户组权限接口操作。", error_code="NOT_IMPLEMENTED")
            else:
                return custom_api_response(False, "缺少 device_id", error_code="MISSING_PARAMETER")
        return custom_api_response(False, "权限修改失败", error_code="VALIDATION_ERROR", details=serializer.errors)


class GroupPermissionsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, group_id, format=None):
        user_group = get_object_or_404(UserGroup, pk=group_id)
        # 获取用户组对设备/设备组的权限
        group_perms = GroupDevicePermission.objects.filter(user_group=user_group)
        serializer = GroupDevicePermissionInfoSerializer(group_perms, many=True)
        return custom_api_response(True, f"用户组 {user_group.name} 的权限获取成功", data=serializer.data)

    def put(self, request, group_id, format=None):
        user_group = get_object_or_404(UserGroup, pk=group_id)
        serializer = GroupPermissionModificationSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            device_id = data.get('device_id')
            device_group_id = data.get('device_group_id')
            permission_level = data['permission_level']

            target_obj = None
            target_kwarg = {}

            if device_id:
                target_obj = get_object_or_404(Device, pk=device_id)
                target_kwarg = {'device': target_obj, 'device_group': None}
            elif device_group_id:
                target_obj = get_object_or_404(DeviceGroup, pk=device_group_id)
                target_kwarg = {'device_group': target_obj, 'device': None}

            if target_obj:
                # 先删除已存在的互斥权限
                if device_id:
                    GroupDevicePermission.objects.filter(user_group=user_group, device_group_id__isnull=False,
                                                         device_id=device_id).delete()
                elif device_group_id:
                    GroupDevicePermission.objects.filter(user_group=user_group, device_id__isnull=False,
                                                         device_group_id=device_group_id).delete()

                permission, created = GroupDevicePermission.objects.update_or_create(
                    user_group=user_group,
                    **target_kwarg,
                    defaults={'permission_level': permission_level}
                )
                msg = "用户组权限已更新。" if not created else "用户组权限已创建。"
                return custom_api_response(True, msg)
            else:
                return custom_api_response(False, "缺少 device_id 或 device_group_id", error_code="MISSING_PARAMETER")

        return custom_api_response(False, "权限修改失败", error_code="VALIDATION_ERROR", details=serializer.errors)


# --- 用户组 (User Groups) ---
class UserGroupViewSet(BaseViewSet):  # 使用 BaseViewSet 来继承默认的 admin 权限
    queryset = UserGroup.objects.prefetch_related('members').all()
    serializer_class = UserGroupSerializer

    # permission_classes = [IsAdminUser] # BaseViewSet 会处理

    def perform_create(self, serializer):
        # serializer.save(created_by=self.request.user) # 如果有 created_by 字段
        serializer.save()

    # 加入用户到组
    @action(detail=True, methods=['post'], url_path='members',
            serializer_class=serializers.Serializer)  # 简单的 Serializer
    def add_member(self, request, pk=None):
        user_group = self.get_object()
        user_id = request.data.get('user_id')
        if not user_id:
            return custom_api_response(False, "缺少 user_id", error_code="MISSING_PARAMETER")

        user_to_add = get_object_or_404(User, pk=user_id)
        user_group.members.add(user_to_add)
        return custom_api_response(True, f"用户 {user_to_add.email} 已加入用户组 {user_group.name}")

    # 从组中移除用户
    @action(detail=True, methods=['delete'], url_path='members/(?P<user_id>[^/.]+)',
            serializer_class=serializers.Serializer)
    def remove_member(self, request, pk=None, user_id=None):
        user_group = self.get_object()
        user_to_remove = get_object_or_404(User, pk=user_id)

        if not user_group.members.filter(pk=user_to_remove.pk).exists():
            return custom_api_response(False, f"用户 {user_to_remove.email} 不在用户组 {user_group.name} 中",
                                       error_code="USER_NOT_IN_GROUP")

        user_group.members.remove(user_to_remove)

        # 文档: "如果用户从public组中移除，删除用户"
        # 假设 'public' 组的名称或 ID 是固定的，例如名称为 "public"
        if user_group.name.lower() == 'public':  # 或者 user_group.id == PUBLIC_GROUP_ID
            # 确保用户不属于任何其他组才删除 (可选逻辑)
            if not user_to_remove.custom_user_groups.exists() and not user_to_remove.groups.exists():  # 检查自定义组和 Django 内置组
                if not user_to_remove.is_staff:  # 一般不删除管理员
                    user_to_remove.delete()
                    return custom_api_response(True, f"用户 {user_to_remove.email} 已从 public 组移除并被删除。")
                else:
                    return custom_api_response(True,
                                               f"用户 {user_to_remove.email} (管理员) 已从 public 组移除，但未被删除。")

        return custom_api_response(True, f"用户 {user_to_remove.email} 已从用户组 {user_group.name} 移除")


# --- 设备组 (Device Groups) ---
class DeviceGroupViewSet(BaseViewSet):
    queryset = DeviceGroup.objects.prefetch_related('devices').all()
    serializer_class = DeviceGroupSerializer

    # permission_classes = [IsAdminUser]

    # 加入设备到组
    @action(detail=True, methods=['post'], url_path='devices', serializer_class=serializers.Serializer)
    def add_device(self, request, pk=None):  # pk is group_id
        device_group = self.get_object()
        device_id = request.data.get('device_id')
        if not device_id:
            return custom_api_response(False, "缺少 device_id", error_code="MISSING_PARAMETER")

        device_to_add = get_object_or_404(Device, pk=device_id)
        device_group.devices.add(device_to_add)
        return custom_api_response(True, f"设备 {device_to_add.name} 已加入设备组 {device_group.name}")

    # 从组中移除设备
    @action(detail=True, methods=['delete'], url_path='devices/(?P<device_id>[^/.]+)',
            serializer_class=serializers.Serializer)
    def remove_device(self, request, pk=None, device_id=None):  # pk is group_id
        device_group = self.get_object()
        device_to_remove = get_object_or_404(Device, pk=device_id)

        if not device_group.devices.filter(pk=device_to_remove.pk).exists():
            return custom_api_response(False, f"设备 {device_to_remove.name} 不在设备组 {device_group.name} 中",
                                       error_code="DEVICE_NOT_IN_GROUP")

        device_group.devices.remove(device_to_remove)

        # 文档: "如果设备从public组中移除，删除设备"
        if device_group.name.lower() == 'public':  # 假设 'public' 设备组
            # 确保设备不属于任何其他组才删除 (可选逻辑)
            if not device_to_remove.device_groups.exists():
                device_to_remove.delete()
                return custom_api_response(True, f"设备 {device_to_remove.name} 已从 public 组移除并被删除。")

        return custom_api_response(True, f"设备 {device_to_remove.name} 已从设备组 {device_group.name} 移除")


# --- 设备 (Devices) ---
class DeviceViewSet(viewsets.ModelViewSet):  # 不使用 BaseViewSet，因为权限更复杂
    queryset = Device.objects.all()

    # serializer_class = DeviceSerializer # 会根据 action 改变

    def get_serializer_class(self):
        if self.action == 'create':  # 对应 "添加设备"
            return DeviceCreateSerializer
        if self.action == 'update' or self.action == 'partial_update':  # 对应 "修改设备信息"
            # 检查请求体是 device_info 字典还是直接的字段
            if 'device_info' in self.request.data and isinstance(self.request.data['device_info'], dict):
                return DeviceInfoDictUpdateSerializer
            return DeviceInfoUpdateSerializer
        return DeviceSerializer  # list, retrieve, destroy

    def get_permissions(self):
        if self.action in ['discover', 'create', 'destroy', 'update', 'partial_update']:
            return [IsAdminUser()]
        # 对于 list (overview), retrieve (detail), control，权限在方法内部或自定义权限类中处理
        return [IsAuthenticated()]

    # POST /devices (添加设备)
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            # 简单假设：通过 ip 和 port 创建设备，实际可能需要更复杂的发现和配对逻辑
            # device_identifier 需要唯一，这里可以考虑从 ip+port 生成或要求提供
            try:
                # 这里的 device_identifier 应该来自设备本身或某种发现机制
                # 暂时用 ip:port 作为标识符，但生产环境需要更可靠的唯一标识
                identifier = f"{data['device_ip']}:{data['device_port']}"
                # 检查是否已存在
                if Device.objects.filter(device_identifier=identifier).exists():
                    return custom_api_response(False, f"设备 {identifier} 已存在。", error_code="DEVICE_ALREADY_EXISTS")

                device = Device.objects.create(
                    name=f"New Device ({identifier})",  # 初始名
                    device_identifier=identifier,
                    ip_address=data['device_ip'],
                    port=data['device_port'],
                    # 其他字段可以有默认值或后续修改
                )
                output_serializer = DeviceSerializer(device)
                return custom_api_response(True, "设备添加成功", data=output_serializer.data,
                                           status_code=status.HTTP_201_CREATED)
            except Exception as e:
                return custom_api_response(False, f"设备添加失败: {str(e)}", error_code="DEVICE_CREATION_FAILED")
        return custom_api_response(False, "设备添加失败", error_code="VALIDATION_ERROR", details=serializer.errors)

    # PUT /devices/{device_id} (修改设备信息)
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(instance, data=request.data, partial=partial)

        if serializer.is_valid():
            if serializer_class == DeviceInfoDictUpdateSerializer:
                device_info = serializer.validated_data.get('device_info', {})
                for key, value in device_info.items():
                    setattr(instance, key, value)
                instance.save()
            else:  # DeviceInfoUpdateSerializer
                serializer.save()

            output_serializer = DeviceSerializer(instance)
            return custom_api_response(True, "设备信息修改成功", data=output_serializer.data)
        return custom_api_response(False, "设备信息修改失败", error_code="VALIDATION_ERROR", details=serializer.errors)

    # DELETE /devices/{device_id} (移除设备)
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        try:
            instance.delete()
            return custom_api_response(True, "设备移除成功", status_code=status.HTTP_204_NO_CONTENT)  # 通常 204 不返回 body
        except Exception as e:
            return custom_api_response(False, f"设备移除失败: {str(e)}", error_code="DEVICE_DELETION_FAILED")

    # GET /devices/discover
    @action(detail=False, methods=['get'], permission_classes=[IsAdminUser])
    def discover(self, request):
        """发现局域网中的virtual-device设备"""
        from utils.device_client import get_device_client

        client = get_device_client()
        discovered_devices_data = []

        try:
            # 扫描常见的IP范围和端口
            ip_ranges = [
                "127.0.0.1",  # 本地测试
                "localhost",  # 本地测试
            ]

            # 可以从配置中获取更多IP范围
            custom_ranges = request.GET.get('ip_ranges', '').split(',')
            if custom_ranges and custom_ranges[0]:
                ip_ranges.extend([ip.strip() for ip in custom_ranges])

            port = 5000  # virtual-device默认端口

            for ip in ip_ranges:
                if not ip:
                    continue

                try:
                    # 尝试查询设备信息
                    result = client.query_device(
                        device_ip=ip,
                        device_port=port,
                        keys=["device_id", "device_type", "power", "status"]
                    )

                    if result.success and result.data:
                        device_info = result.data
                        device_identifier = device_info.get("device_id", f"{ip}:{port}")

                        # 检查设备是否已存在于数据库
                        existing_device = Device.objects.filter(
                            device_identifier=device_identifier
                        ).first()

                        discovered_device = {
                            "device_identifier": device_identifier,
                            "name": f"{device_info.get('device_type', 'Unknown')} ({device_identifier})",
                            "ip": ip,
                            "port": port,
                            "device_type": device_info.get("device_type", "unknown"),
                            "status": device_info.get("status", "unknown"),
                            "power": device_info.get("power", 0),
                            "already_added": existing_device is not None,
                            "database_id": existing_device.id if existing_device else None
                        }

                        discovered_devices_data.append(discovered_device)

                except Exception as e:
                    # 单个IP扫描失败不影响其他IP
                    continue

            if discovered_devices_data:
                return custom_api_response(
                    True,
                    f"发现 {len(discovered_devices_data)} 个设备",
                    data=discovered_devices_data
                )
            else:
                return custom_api_response(
                    True,
                    "未发现任何设备，请确保virtual-device正在运行",
                    data=[]
                )

        except Exception as e:
            return custom_api_response(
                False,
                f"设备发现过程中发生错误: {str(e)}",
                error_code="DISCOVERY_ERROR"
            )

    # POST /devices/sync
    @action(detail=False, methods=['post'], permission_classes=[IsAdminUser])
    def sync(self, request):
        """同步发现的设备到数据库"""
        device_data = request.data.get('device_data')

        if not device_data:
            return custom_api_response(False, "缺少设备数据", error_code="MISSING_DEVICE_DATA")

        from utils.device_client import get_device_client
        client = get_device_client()

        try:
            synced_devices = []
            errors = []

            # 如果传入的是单个设备，转换为列表
            if isinstance(device_data, dict):
                device_data = [device_data]

            for device_info in device_data:
                try:
                    device_identifier = device_info.get('device_identifier')
                    ip = device_info.get('ip')
                    port = device_info.get('port', 5000)

                    if not device_identifier or not ip:
                        errors.append(f"设备信息不完整: {device_info}")
                        continue

                    # 检查设备是否已存在
                    existing_device = Device.objects.filter(
                        device_identifier=device_identifier
                    ).first()

                    if existing_device:
                        # 更新现有设备
                        existing_device.ip_address = ip
                        existing_device.port = port
                        existing_device.name = device_info.get('name', existing_device.name)
                        existing_device.device_type = device_info.get('device_type', existing_device.device_type)
                        existing_device.save()
                        synced_devices.append({
                            'action': 'updated',
                            'device_id': existing_device.id,
                            'device_identifier': device_identifier
                        })
                    else:
                        # 创建新设备
                        new_device = Device.objects.create(
                            name=device_info.get('name', f"Device {device_identifier}"),
                            device_identifier=device_identifier,
                            ip_address=ip,
                            port=port,
                            device_type=device_info.get('device_type', 'unknown'),
                            status=device_info.get('status', 'offline')
                        )
                        synced_devices.append({
                            'action': 'created',
                            'device_id': new_device.id,
                            'device_identifier': device_identifier
                        })

                    # 尝试获取设备的最新状态
                    try:
                        result = client.query_device(
                            device_ip=ip,
                            device_port=port,
                            keys=["device_id", "device_type", "status", "power"]
                        )

                        if result.success and result.data:
                            device = Device.objects.get(device_identifier=device_identifier)
                            device.status = result.data.get('status', device.status)
                            device.current_power_consumption = result.data.get('power', device.current_power_consumption)
                            device.save()
                    except Exception:
                        # 状态同步失败不影响设备创建/更新
                        pass

                except Exception as e:
                    errors.append(f"同步设备 {device_info.get('device_identifier', 'unknown')} 失败: {str(e)}")

            result_data = {
                'synced_devices': synced_devices,
                'errors': errors,
                'total_processed': len(device_data),
                'successful': len(synced_devices),
                'failed': len(errors)
            }

            if synced_devices:
                return custom_api_response(
                    True,
                    f"成功同步 {len(synced_devices)} 个设备",
                    data=result_data
                )
            else:
                return custom_api_response(
                    False,
                    "没有设备被同步",
                    error_code="NO_DEVICES_SYNCED",
                    data=result_data
                )

        except Exception as e:
            return custom_api_response(
                False,
                f"设备同步过程中发生错误: {str(e)}",
                error_code="SYNC_ERROR"
            )

    # POST /devices/{device_id}/control
    @action(detail=True, methods=['post'],
            permission_classes=[IsAuthenticated, CanControlDevice])  # CanControlDevice 会检查权限
    def control(self, request, pk=None):
        device = self.get_object()  # get_object 会自动处理 404，CanControlDevice 会检查权限

        action_name = request.data.get('action')
        parameters = request.data.get('parameters', {})

        if not action_name:
            return custom_api_response(False, "缺少操作参数 'action'", error_code="MISSING_ACTION")

        # 检查设备是否有IP和端口信息
        if not device.ip_address or not device.port:
            return custom_api_response(False, f"设备 {device.name} 缺少网络配置信息", error_code="DEVICE_CONFIG_MISSING")

        # 使用设备通信客户端进行真实的设备控制
        from utils.device_client import get_device_client

        client = get_device_client()

        try:
            # 发送控制命令到真实设备
            result = client.control_device(
                device_ip=device.ip_address,
                device_port=device.port,
                action=action_name,
                params=parameters
            )

            if result.success:
                # 控制成功，更新设备状态
                control_success = result.data.get("success", False) if result.data else False

                if control_success:
                    # 根据操作类型更新设备状态
                    if action_name in ["turn_on", "switch"] and parameters.get("state") == "on":
                        device.status = 'online'
                    elif action_name in ["turn_off", "switch"] and parameters.get("state") == "off":
                        device.status = 'offline'

                    device.save()

                    # 记录使用日志
                    DeviceUsageRecord.objects.create(
                        device=device,
                        user=request.user,
                        action=action_name,
                        parameters=parameters
                    )

                    control_message = f"设备 {device.name} 控制成功: {action_name}"
                    return custom_api_response(True, control_message, data=result.data)
                else:
                    # 设备返回失败
                    error_msg = result.data.get("error", "设备控制失败") if result.data else "设备控制失败"
                    return custom_api_response(False, f"设备 {device.name} 控制失败: {error_msg}",
                                             error_code="DEVICE_CONTROL_FAILED", details=result.data)
            else:
                # 通信失败
                return custom_api_response(False, f"无法与设备 {device.name} 通信: {result.error}",
                                         error_code="DEVICE_COMMUNICATION_FAILED")

        except Exception as e:
            # 异常处理
            return custom_api_response(False, f"设备控制异常: {str(e)}", error_code="CONTROL_EXCEPTION")


# GET /devices/overview
class DeviceOverviewView(generics.ListAPIView):
    serializer_class = DeviceOverviewSerializer
    permission_classes = [IsAuthenticated]  # 基础认证

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:  # 管理员看所有
            return Device.objects.all()

        # 普通用户：至少有 'visible' 权限的设备
        # 1. 直接分配给用户的设备
        user_device_ids = UserDevicePermission.objects.filter(
            user=user,
            permission_level__in=[PermissionLevel.VISIBLE, PermissionLevel.USABLE, PermissionLevel.CONFIGURABLE,
                                  PermissionLevel.MONITORABLE, PermissionLevel.MANAGEABLE]
        ).values_list('device_id', flat=True)

        # 2. 用户所在组有权限的设备
        user_groups = user.custom_user_groups.all()  # 或 user.groups.all()
        group_device_ids = GroupDevicePermission.objects.filter(
            user_group__in=user_groups,
            device__isnull=False,  # 确保是设备权限，不是设备组权限
            permission_level__in=[PermissionLevel.VISIBLE, PermissionLevel.USABLE, PermissionLevel.CONFIGURABLE,
                                  PermissionLevel.MONITORABLE, PermissionLevel.MANAGEABLE]
        ).values_list('device_id', flat=True)

        # 3. 用户所在组有权限的设备组中的设备
        # (这部分更复杂，如果需要，需要进一步查询)

        # 合并并去重
        visible_device_ids = set(list(user_device_ids) + list(group_device_ids))
        return Device.objects.filter(pk__in=list(visible_device_ids))

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return custom_api_response(True, "设备概要获取成功", data=serializer.data)


# GET /devices/{device_id}/detail
class DeviceDetailView(generics.RetrieveAPIView):
    queryset = Device.objects.prefetch_related('logs', 'usage_records__user').all()  # prefetch logs and usage_records
    serializer_class = DeviceDetailSerializer
    permission_classes = [IsAuthenticated, CanMonitorDevice]  # CanMonitorDevice 会检查对象权限
    lookup_field = 'pk'  # or 'device_id' if your URL uses that

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()  # get_object() checks permissions via CanMonitorDevice
        serializer = self.get_serializer(instance)
        # 补充运行日志和使用记录 (如果模型中没有直接关联，需要在这里查询)
        # DeviceDetailSerializer 已经通过 related_name 'logs' 和 'usage_records' 处理了
        return custom_api_response(True, "设备详情获取成功", data=serializer.data)


# POST /devices/heartbeat
class DeviceHeartbeatView(APIView):
    permission_classes = [AllowAny]  # 设备心跳通常不需要用户 token，可能需要设备自身的认证 (例如 API Key)
    serializer_class = DeviceHeartbeatSerializer

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            device_identifier = data['device_identifier']

            try:
                device = Device.objects.get(device_identifier=device_identifier)
                device.status = data['status']
                device.last_heartbeat = data['timestamp']  # 确保 timestamp 是 timezone-aware

                heartbeat_data_payload = data.get('data', {})
                if 'current_power_consumption' in heartbeat_data_payload:
                    device.current_power_consumption = heartbeat_data_payload['current_power_consumption']
                # 更新其他来自心跳的数据...
                # 例如，如果心跳包里有 uptime，可以更新 device.uptime_seconds

                device.save()

                # 记录心跳日志
                log_message = f"心跳更新: 状态={data['status']}"
                if 'current_power_consumption' in heartbeat_data_payload:
                    log_message += f", 功耗={heartbeat_data_payload['current_power_consumption']}W"

                DeviceLog.objects.create(device=device, log_message=log_message)

                return custom_api_response(True, f"设备 {device_identifier} 心跳已接收并更新")
            except Device.DoesNotExist:
                return custom_api_response(False, f"设备标识符 {device_identifier} 未找到",
                                           error_code="DEVICE_NOT_FOUND", status_code=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return custom_api_response(False, f"心跳处理失败: {str(e)}", error_code="HEARTBEAT_ERROR")
        return custom_api_response(False, "心跳数据无效", error_code="VALIDATION_ERROR", details=serializer.errors)