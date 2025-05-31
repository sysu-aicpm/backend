classDiagram
direction BT
class api_device {
   varchar(100) name
   varchar(100) device_identifier
   char(39) ip_address
   int unsigned port
   varchar(50) device_type
   varchar(50) brand
   longtext description
   varchar(20) status
   double current_power_consumption
   int unsigned uptime_seconds
   datetime(6) last_heartbeat
   bigint id
}
class api_devicegroup {
   varchar(100) name
   longtext description
   bigint id
}
class api_devicegroup_devices {
   bigint devicegroup_id
   bigint device_id
   bigint id
}
class api_devicelog {
   datetime(6) timestamp
   longtext log_message
   bigint device_id
   bigint id
}
class api_deviceusagerecord {
   varchar(100) action
   datetime(6) timestamp
   json parameters
   bigint device_id
   bigint user_id
   bigint id
}
class api_groupdevicepermission {
   varchar(20) permission_level
   bigint device_id
   bigint device_group_id
   bigint user_group_id
   bigint id
}
class api_user {
   varchar(128) password
   datetime(6) last_login
   tinyint(1) is_superuser
   varchar(150) username
   varchar(150) first_name
   varchar(150) last_name
   tinyint(1) is_staff
   tinyint(1) is_active
   datetime(6) date_joined
   varchar(254) email
   bigint id
}
class api_user_groups {
   bigint user_id
   int group_id
   bigint id
}
class api_user_user_permissions {
   bigint user_id
   int permission_id
   bigint id
}
class api_userdevicepermission {
   varchar(20) permission_level
   bigint device_id
   bigint user_id
   bigint id
}
class api_usergroup {
   varchar(100) name
   longtext description
   bigint id
}
class api_usergroup_members {
   bigint usergroup_id
   bigint user_id
   bigint id
}
class auth_group {
   varchar(150) name
   int id
}
class auth_group_permissions {
   int group_id
   int permission_id
   bigint id
}
class auth_permission {
   varchar(255) name
   int content_type_id
   varchar(100) codename
   int id
}
class auth_user {
   varchar(128) password
   datetime(6) last_login
   tinyint(1) is_superuser
   varchar(150) username
   varchar(150) first_name
   varchar(150) last_name
   varchar(254) email
   tinyint(1) is_staff
   tinyint(1) is_active
   datetime(6) date_joined
   int id
}
class auth_user_groups {
   int user_id
   int group_id
   bigint id
}
class auth_user_user_permissions {
   int user_id
   int permission_id
   bigint id
}
class django_admin_log {
   datetime(6) action_time
   longtext object_id
   varchar(200) object_repr
   smallint unsigned action_flag
   longtext change_message
   int content_type_id
   int user_id
   int id
}
class django_content_type {
   varchar(100) app_label
   varchar(100) model
   int id
}
class django_migrations {
   varchar(255) app
   varchar(255) name
   datetime(6) applied
   bigint id
}
class django_session {
   longtext session_data
   datetime(6) expire_date
   varchar(40) session_key
}

api_devicegroup_devices  -->  api_device : device_id:id
api_devicegroup_devices  -->  api_devicegroup : devicegroup_id:id
api_devicelog  -->  api_device : device_id:id
api_deviceusagerecord  -->  api_device : device_id:id
api_deviceusagerecord  -->  api_user : user_id:id
api_groupdevicepermission  -->  api_device : device_id:id
api_groupdevicepermission  -->  api_devicegroup : device_group_id:id
api_groupdevicepermission  -->  api_usergroup : user_group_id:id
api_user_groups  -->  api_user : user_id:id
api_user_groups  -->  auth_group : group_id:id
api_user_user_permissions  -->  api_user : user_id:id
api_user_user_permissions  -->  auth_permission : permission_id:id
api_userdevicepermission  -->  api_device : device_id:id
api_userdevicepermission  -->  api_user : user_id:id
api_usergroup_members  -->  api_user : user_id:id
api_usergroup_members  -->  api_usergroup : usergroup_id:id
auth_group_permissions  -->  auth_group : group_id:id
auth_group_permissions  -->  auth_permission : permission_id:id
auth_permission  -->  django_content_type : content_type_id:id
auth_user_groups  -->  auth_group : group_id:id
auth_user_groups  -->  auth_user : user_id:id
auth_user_user_permissions  -->  auth_permission : permission_id:id
auth_user_user_permissions  -->  auth_user : user_id:id
django_admin_log  -->  auth_user : user_id:id
django_admin_log  -->  django_content_type : content_type_id:id
