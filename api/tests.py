import json

from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from .models import (
    User, Device, DeviceGroup, UserGroup,
    UserDevicePermission, GroupDevicePermission, PermissionLevel,
    DeviceLog, DeviceUsageRecord # Import if you plan to test their creation via side effects
)

# User = get_user_model()

# Define constants for "public" group names if you have special logic for them
PUBLIC_USER_GROUP_NAME = "public_users" # Example name
PUBLIC_DEVICE_GROUP_NAME = "public_devices" # Example name

def debug_print_response(response, message="API Response"):
    print(f"\n🔍 DEBUG: {message} 🕵️")
    print(f"URL: {response.request.get('PATH_INFO', 'N/A')}")
    print(f"Status Code: {response.status_code}")
    print("Headers:", response.headers)
    try:
        print("JSON Data (parsed):")
        print(json.dumps(response.data, indent=2, ensure_ascii=False))
    except (json.JSONDecodeError, TypeError):
        print("Raw Content (could not parse as JSON or not applicable):")
        print(response.content.decode(errors='replace')) # Decode bytes to string
    print("-" * 50 + "\n")


class BaseAPITestCase(APITestCase):
    """
    Base class for API tests, includes common setup and helper methods.
    """
    def setUp(self):
        super().setUp() # Call parent setUp if it exists or you add one

        # Common Users
        self.admin_password = 'AdminPassword123!'
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            username='adminuser', # Django superuser creation might still require username
            password=self.admin_password
        )

        self.user1_password = 'UserPassword123!'
        self.user1 = User.objects.create_user(
            email='user1@example.com',
            username='user1',
            password=self.user1_password
        )

        self.user2_password = 'User2Password123!'
        self.user2 = User.objects.create_user(
            email='user2@example.com',
            username='user2',
            password=self.user2_password
        )

        # Common Devices
        self.device1 = Device.objects.create(name="Living Room Lamp", device_identifier="lamp_lr_001", device_type="light", status="offline")
        self.device2 = Device.objects.create(name="Kitchen AC", device_identifier="ac_kitchen_002", device_type="air_conditioner", status="online")
        self.device_to_delete = Device.objects.create(name="Old Fan", device_identifier="fan_old_003", device_type="fan")


        # Common User Groups
        self.ug1 = UserGroup.objects.create(name="Technicians")
        self.ug1.members.add(self.user1)
        self.public_user_group, _ = UserGroup.objects.get_or_create(name=PUBLIC_USER_GROUP_NAME)
        self.public_user_group.members.add(self.user2)


        # Common Device Groups
        self.dg1 = DeviceGroup.objects.create(name="Living Room Devices")
        self.dg1.devices.add(self.device1)
        self.public_device_group, _ = DeviceGroup.objects.get_or_create(name=PUBLIC_DEVICE_GROUP_NAME)
        self.public_device_group.devices.add(self.device2)


    def _login_user(self, email, password):
        """Helper to login a user and return the token."""
        response = self.client.post(reverse('api_v1:auth-login'), {'email': email, 'password': password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK, f"Login failed for {email}: {response.data}")
        self.assertTrue(response.data.get('success'), f"Login success flag False for {email}: {response.data}")
        token = response.data.get('data', {}).get('token')
        self.assertIsNotNone(token, f"Token not found in login response for {email}: {response.data}")
        return token

    def _set_auth_bearer(self, token):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def _login_and_set_auth(self, email, password):
        token = self._login_user(email, password)
        self._set_auth_bearer(token)

    def _assert_common_success_response(self, response, status_code=status.HTTP_200_OK):
        debug_print_response(response, "Response from 'some specific endpoint'")
        self.assertEqual(response.status_code, status_code)
        self.assertTrue(response.data.get('success'))
        self.assertIsNotNone(response.data.get('message'))

    def _assert_common_error_response(self, response, status_code, error_code=None):
        debug_print_response(response, "Response from 'some specific endpoint'")
        self.assertEqual(response.status_code, status_code)
        self.assertFalse(response.data.get('success'))
        self.assertIsNotNone(response.data.get('message'))
        if error_code:
            self.assertEqual(response.data.get('error_code'), error_code)

# --- Account Tests ---
class AccountAuthAPITests(BaseAPITestCase):

    def test_register_user_success(self):
        url = reverse('api_v1:auth-register')
        data = {'email': 'newuser@example.com', 'username': 'newuser', 'password': 'NewPassword123!'}
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response) # Your API returns 200 OK on register
        self.assertTrue(User.objects.filter(email=data['email']).exists())

    def test_register_user_email_exists(self):
        url = reverse('api_v1:auth-register')
        data = {'email': self.user1.email, 'username': 'anotheruser', 'password': 'Password123!'}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_400_BAD_REQUEST, "VALIDATION_ERROR")

    def test_register_user_missing_fields(self):
        url = reverse('api_v1:auth-register')
        response = self.client.post(url, {'email': 'missingpass@example.com'}, format='json')
        self._assert_common_error_response(response, status.HTTP_400_BAD_REQUEST, "VALIDATION_ERROR")

    def test_login_user_success(self):
        # Tested in BaseAPITestCase._login_user, but can be explicit here too
        url = reverse('api_v1:auth-login')
        data = {'email': self.user1.email, 'password': self.user1_password}
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response)
        self.assertIn('token', response.data.get('data', {}))
        self.assertIn('refresh_token', response.data.get('data', {}))

    def test_login_user_wrong_password(self):
        url = reverse('api_v1:auth-login')
        data = {'email': self.user1.email, 'password': 'WrongPassword!'}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_401_UNAUTHORIZED, "LOGIN_FAILED")

    def test_login_user_nonexistent(self):
        url = reverse('api_v1:auth-login')
        data = {'email': 'nosuchuser@example.com', 'password': 'Password123!'}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_401_UNAUTHORIZED, "LOGIN_FAILED")

    def test_get_user_info_success(self):
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:auth-me')
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertEqual(response.data['data']['email'], self.user1.email)

    def test_get_user_info_unauthenticated(self):
        url = reverse('api_v1:auth-me')
        response = self.client.get(url, format='json')
        self._assert_common_error_response(response, status.HTTP_401_UNAUTHORIZED)

    def test_update_user_info_success(self):
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:auth-me')
        new_first_name = "UpdatedFirstName"
        data = {'first_name': new_first_name, 'last_name': 'UpdatedLastName'}
        response = self.client.put(url, data, format='json') # Assuming PUT, or PATCH if partial
        self._assert_common_success_response(response)
        self.user1.refresh_from_db()
        self.assertEqual(self.user1.first_name, new_first_name)

    def test_update_user_info_change_password(self):
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:auth-me')
        new_password = "NewSecurePassword123!"
        data = {'password': new_password}
        response = self.client.put(url, data, format='json')
        self._assert_common_success_response(response)
        # Verify new password by trying to log in with it
        self.client.credentials() # Clear old auth
        login_response = self.client.post(reverse('api_v1:auth-login'), {'email': self.user1.email, 'password': new_password}, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)


# --- Permissions API Tests ---
class PermissionsAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        # Grant user1 'visible' permission to device1
        UserDevicePermission.objects.create(user=self.user1, device=self.device1, permission_level=PermissionLevel.VISIBLE)

    def test_get_user_permissions_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:user-permissions', kwargs={'user_id': self.user1.id})
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertIsInstance(response.data['data'], list)
        found_perm = any(p['id'] == self.device1.id and p['permission'] == PermissionLevel.VISIBLE for p in response.data['data'])
        self.assertTrue(found_perm)

    def test_get_user_permissions_as_regular_user_forbidden(self):
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:user-permissions', kwargs={'user_id': self.user2.id})
        response = self.client.get(url, format='json')
        self._assert_common_error_response(response, status.HTTP_403_FORBIDDEN)

    def test_get_user_permissions_user_not_found_as_admin(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:user-permissions', kwargs={'user_id': 9999})
        response = self.client.get(url, format='json')
        self._assert_common_error_response(response, status.HTTP_404_NOT_FOUND)

    def test_update_user_permission_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:user-permissions', kwargs={'user_id': self.user1.id})
        data = {'device_id': self.device2.id, 'permission_level': PermissionLevel.USABLE}
        response = self.client.put(url, data, format='json')
        self._assert_common_success_response(response)
        self.assertTrue(UserDevicePermission.objects.filter(user=self.user1, device=self.device2, permission_level=PermissionLevel.USABLE).exists())

    # ... Add more tests for PUT /permissions/user/{user_id} (device not found, invalid level, etc.)

    def test_get_group_permissions_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        # Setup a group permission
        GroupDevicePermission.objects.create(user_group=self.ug1, device=self.device1, permission_level=PermissionLevel.MONITORABLE)
        url = reverse('api_v1:group-permissions', kwargs={'group_id': self.ug1.id})
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        found_perm = any(p.get('id') == self.device1.id and p.get('permission') == PermissionLevel.MONITORABLE for p in response.data['data'])
        self.assertTrue(found_perm, f"Permission not found in response: {response.data['data']}")


    def test_update_group_permission_device_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:group-permissions', kwargs={'group_id': self.ug1.id})
        data = {'device_id': self.device2.id, 'permission_level': PermissionLevel.CONFIGURABLE}
        response = self.client.put(url, data, format='json')
        self._assert_common_success_response(response)
        self.assertTrue(GroupDevicePermission.objects.filter(user_group=self.ug1, device=self.device2, permission_level=PermissionLevel.CONFIGURABLE).exists())

    def test_update_group_permission_device_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:group-permissions', kwargs={'group_id': self.ug1.id})
        data = {'device_group_id': self.dg1.id, 'permission_level': PermissionLevel.USABLE}
        response = self.client.put(url, data, format='json')
        self._assert_common_success_response(response)
        self.assertTrue(GroupDevicePermission.objects.filter(user_group=self.ug1, device_group=self.dg1, permission_level=PermissionLevel.USABLE).exists())

    # ... Add more tests for PUT /permissions/group/{group_id} (validation errors, etc.)


# --- User Group API Tests ---
class UserGroupAPITests(BaseAPITestCase):
    def test_create_user_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:usergroup-list') # ViewSet default name for list/create
        data = {'name': 'New User Group', 'description': 'A test group.'}
        response = self.client.post(url, data, format='json')
        # Your create might return 200 OK with custom response or 201 Created for standard DRF
        # Adjust based on your BaseViewSet or view implementation
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
        if response.status_code == status.HTTP_200_OK: # If using custom_api_response for create
            self.assertTrue(response.data.get('success'))
        self.assertTrue(UserGroup.objects.filter(name=data['name']).exists())

    def test_create_user_group_as_regular_user_forbidden(self):
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:usergroup-list')
        data = {'name': 'Forbidden Group'}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_403_FORBIDDEN)

    # ... Add tests for list, retrieve, update, delete UserGroup (as admin)
    # ... Add tests for name uniqueness on create/update

    def test_add_member_to_user_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:usergroup-add-member', kwargs={'pk': self.ug1.id})
        data = {'user_id': self.user2.id}
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response)
        self.ug1.refresh_from_db()
        self.assertIn(self.user2, self.ug1.members.all())

    def test_remove_member_from_user_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        self.assertTrue(self.user1 in self.ug1.members.all()) # Pre-condition
        url = reverse('api_v1:usergroup-remove-member', kwargs={'pk': self.ug1.id, 'user_id': self.user1.id})
        response = self.client.delete(url, format='json')
        self._assert_common_success_response(response)
        self.ug1.refresh_from_db()
        self.assertNotIn(self.user1, self.ug1.members.all())

    def test_remove_member_from_public_user_group_deletes_user(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        user2_id = self.user2.id # user2 is in public_user_group and no other group
        self.assertTrue(self.user2 in self.public_user_group.members.all())

        url = reverse('api_v1:usergroup-remove-member', kwargs={'pk': self.public_user_group.id, 'user_id': user2_id})
        response = self.client.delete(url, format='json')
        self._assert_common_success_response(response) # Check the specific message if it indicates deletion
        self.assertFalse(User.objects.filter(id=user2_id).exists())


# --- Device Group API Tests ---
class DeviceGroupAPITests(BaseAPITestCase):
    def test_create_device_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:devicegroup-list')
        data = {'name': 'New Device Group', 'description': 'A test device group.'}
        response = self.client.post(url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_201_CREATED])
        if response.status_code == status.HTTP_200_OK:
             self.assertTrue(response.data.get('success'))
        self.assertTrue(DeviceGroup.objects.filter(name=data['name']).exists())

    # ... Add tests for list, retrieve, update, delete DeviceGroup (as admin)

    def test_add_device_to_device_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:devicegroup-add-device', kwargs={'pk': self.dg1.id})
        data = {'device_id': self.device2.id} # Add device2 to dg1
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response)
        self.dg1.refresh_from_db()
        self.assertIn(self.device2, self.dg1.devices.all())

    def test_remove_device_from_device_group_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        self.assertTrue(self.device1 in self.dg1.devices.all()) # Pre-condition
        url = reverse('api_v1:devicegroup-remove-device', kwargs={'pk': self.dg1.id, 'device_id': self.device1.id})
        response = self.client.delete(url, format='json')
        self._assert_common_success_response(response)
        self.dg1.refresh_from_db()
        self.assertNotIn(self.device1, self.dg1.devices.all())

    def test_remove_device_from_public_device_group_deletes_device(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        # device2 is in public_device_group and no other group initially by setup
        device2_id = self.device2.id
        self.assertTrue(self.device2 in self.public_device_group.devices.all())

        url = reverse('api_v1:devicegroup-remove-device', kwargs={'pk': self.public_device_group.id, 'device_id': device2_id})
        response = self.client.delete(url, format='json')
        self._assert_common_success_response(response)
        self.assertFalse(Device.objects.filter(id=device2_id).exists())


# --- Device API Tests ---
class DeviceAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        # Grant user1 specific permissions for detailed tests
        UserDevicePermission.objects.create(user=self.user1, device=self.device1, permission_level=PermissionLevel.MONITORABLE)
        UserDevicePermission.objects.create(user=self.user1, device=self.device2, permission_level=PermissionLevel.USABLE)

        # User2 has no direct permissions initially, only via groups if any

    def test_discover_devices_as_admin_success(self): # Mocked response
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-discover')
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertIsInstance(response.data['data'], list)
        # Check for expected keys if your mock provides them
        if response.data['data']:
             self.assertIn("name", response.data['data'][0])
             self.assertIn("ip", response.data['data'][0])

    def test_add_device_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-list') # Create action
        data = {"device_ip": "10.0.1.10", "device_port": "2100"}
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response, status_code=status.HTTP_201_CREATED)
        self.assertTrue(Device.objects.filter(device_identifier="10.0.1.10:2100").exists())

    def test_add_device_duplicate_identifier_fails(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-list')
        # device1 identifier is "lamp_lr_001"
        # Let's assume the create logic for device_ip and device_port uses "ip:port" as identifier
        existing_ip_port_device = Device.objects.create(name="PreExisting", device_identifier="10.0.1.11:2101", ip_address="10.0.1.11", port=2101)
        data = {"device_ip": existing_ip_port_device.ip_address, "device_port": str(existing_ip_port_device.port)}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_400_BAD_REQUEST, "DEVICE_ALREADY_EXISTS")


    def test_remove_device_as_admin_success(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-detail', kwargs={'pk': self.device_to_delete.id}) # Destroy action
        response = self.client.delete(url, format='json')
        # Your custom response for 204 might still send a body
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT])
        if response.status_code == status.HTTP_200_OK: # If your custom_api_response is used for 204
             self.assertTrue(response.data.get('success'))
        self.assertFalse(Device.objects.filter(id=self.device_to_delete.id).exists())

    def test_modify_device_info_as_admin_success_direct_fields(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-detail', kwargs={'pk': self.device1.id}) # Update action
        new_name = "Updated Living Room Lamp"
        data = {"name": new_name, "description": "Now smarter."}
        response = self.client.put(url, data, format='json') # Use PATCH for partial update
        self._assert_common_success_response(response)
        self.device1.refresh_from_db()
        self.assertEqual(self.device1.name, new_name)

    def test_modify_device_info_as_admin_success_device_info_dict(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-detail', kwargs={'pk': self.device1.id})
        new_brand = "SuperBrand"
        data = {"device_info": {"brand": new_brand, "name": "Brand New Name"}}
        response = self.client.put(url, data, format='json')
        self._assert_common_success_response(response)
        self.device1.refresh_from_db()
        self.assertEqual(self.device1.brand, new_brand)
        self.assertEqual(self.device1.name, "Brand New Name")

    def test_control_device_user_with_usable_permission_success(self):
        self._login_and_set_auth(self.user1.email, self.user1_password) # user1 has 'usable' for device2
        url = reverse('api_v1:device-control', kwargs={'pk': self.device2.id})
        data = {"action": "turn_on", "parameters": {}}
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response)
        self.device2.refresh_from_db()
        self.assertEqual(self.device2.status, "online") # Assuming 'turn_on' sets status to 'online'

    def test_control_device_user_without_usable_permission_forbidden(self):
        # user1 has 'monitorable' for device1, not 'usable'
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:device-control', kwargs={'pk': self.device1.id})
        data = {"action": "turn_on"}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_403_FORBIDDEN)

    def test_get_device_overview_as_admin_sees_all(self):
        self._login_and_set_auth(self.admin_user.email, self.admin_password)
        url = reverse('api_v1:device-overview')
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertEqual(len(response.data['data']), Device.objects.count())

    def test_get_device_overview_as_regular_user_sees_permitted(self):
        # user1 has 'monitorable' (>= visible) on device1 and 'usable' (>= visible) on device2
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:device-overview')
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertEqual(len(response.data['data']), 2) # Should see device1 and device2
        device_ids_in_response = {d['id'] for d in response.data['data']}
        self.assertIn(self.device1.id, device_ids_in_response)
        self.assertIn(self.device2.id, device_ids_in_response)

    def test_get_device_detail_user_with_monitorable_permission_success(self):
        # user1 has 'monitorable' for device1
        self._login_and_set_auth(self.user1.email, self.user1_password)
        url = reverse('api_v1:device-detail', kwargs={'pk': self.device1.id})
        response = self.client.get(url, format='json')
        self._assert_common_success_response(response)
        self.assertEqual(response.data['data']['name'], self.device1.name)
        self.assertIn('logs', response.data['data']) # Check for detail fields

    def test_get_device_detail_user_with_usable_but_not_monitorable_permission_forbidden(self):
        # Grant user2 'usable' but not 'monitorable' for device1
        UserDevicePermission.objects.create(user=self.user2, device=self.device1, permission_level=PermissionLevel.USABLE)
        self._login_and_set_auth(self.user2.email, self.user2_password)
        url = reverse('api_v1:device-detail', kwargs={'pk': self.device1.id})
        response = self.client.get(url, format='json')
        self._assert_common_error_response(response, status.HTTP_403_FORBIDDEN)

    def test_device_heartbeat_success(self):
        url = reverse('api_v1:device-heartbeat')
        timestamp_str = "2025-05-30T10:00:00Z"
        data = {
            "device_identifier": self.device1.device_identifier,
            "timestamp": timestamp_str,
            "status": "online",
            "data": {"current_power_consumption": 100.5}
        }
        response = self.client.post(url, data, format='json')
        self._assert_common_success_response(response)
        self.device1.refresh_from_db()
        self.assertEqual(self.device1.status, "online")
        self.assertEqual(self.device1.current_power_consumption, 100.5)
        # self.assertEqual(self.device1.last_heartbeat.isoformat(), timestamp_str.replace("Z", "+00:00")) # Compare timezone-aware datetime

    def test_device_heartbeat_device_not_found(self):
        url = reverse('api_v1:device-heartbeat')
        data = {"device_identifier": "nonexistent_device_XXX", "timestamp": "2025-05-30T10:00:00Z", "status": "online"}
        response = self.client.post(url, data, format='json')
        self._assert_common_error_response(response, status.HTTP_404_NOT_FOUND, "DEVICE_NOT_FOUND")