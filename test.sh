## 1. 登录并获取 Token
#LOGIN_RESPONSE=$(curl -s -X POST \
#  -H "Content-Type: application/json" \
#  -d '{"email": "ykx@abc.com", "password": "ykx"}' \
#  http://127.0.0.1:8000/api/v1/auth/login/)
#
## 2. 从响应中提取 Access Token (需要 jq 工具)
#ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r .access)
#
## 如果没有 jq，你需要手动从 LOGIN_RESPONSE 的输出中复制 access token
## echo $LOGIN_RESPONSE # 然后手动复制 access token
#
## 检查 ACCESS_TOKEN 是否获取成功
#echo "Access Token: $ACCESS_TOKEN"
#
## 如果 ACCESS_TOKEN 为空或 "null"，请检查登录凭据和登录接口的响应
#if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
#  echo "错误：未能获取 Access Token。请检查你的用户名和密码以及登录接口的响应。"
#  echo "登录响应内容: $LOGIN_RESPONSE"
#  exit 1
#fi
#
#curl -X GET \
#  -H "Authorization: Bearer $ACCESS_TOKEN" \
#  http://127.0.0.1:8000/api/v1/auth/me/ | jq
#
#curl -X PUT \
#  -H "Authorization: Bearer $ACCESS_TOKEN" \
#  -H "Content-Type: application/json" \
#  -d '{"first_name": "新的名字", "last_name": "新的姓氏"}' \
#  http://127.0.0.1:8000/api/v1/auth/me/ | jq

#!/bin/bash

# --- Configuration ---
SERVER_ADDRESS="http://127.0.0.1:8080"
API_BASE_URL="${SERVER_ADDRESS}/api/v1"

# Credentials for an existing admin user (LOGIN IS NOW EMAIL-BASED)
ADMIN_EMAIL="admin@admin.com" # CHANGE THIS to your admin's email
ADMIN_PASSWORD="admin"  # CHANGE THIS

# Credentials for a new user to be registered
# Login for this new user will also be email-based
NEW_USER_EMAIL="testuser$(date +%s)@example.com" # Unique email using timestamp
NEW_USER_USERNAME="testuser$(date +%s)" # Username might still be needed for User model creation via RegisterSerializer
NEW_USER_PASSWORD="testpassword123"

# To store tokens
ADMIN_TOKEN=""
USER_TOKEN=""
USER_REFRESH_TOKEN=""
NEW_USER_ID="" # Will be set after registration and login of new user

# To store created resource IDs
TEST_USER_GROUP_ID=""
TEST_DEVICE_GROUP_ID=""
TEST_DEVICE_ID=""
TEST_DEVICE_IDENTIFIER="test-device-$(date +%s)" # For heartbeat and device creation

# --- Helper Functions ---
# Function to make API calls and print details
# Usage: call_api "METHOD" "ENDPOINT" "JSON_DATA_STRING (or empty)" "TOKEN_TYPE (admin/user/none)" "CONTENT_TYPE (optional, defaults to application/json if JSON_DATA_STRING is provided)"
call_api() {
    METHOD="$1"
    ENDPOINT="$2"
    JSON_DATA="$3" # Renamed for clarity, expected to be a JSON string or empty
    TOKEN_TYPE="$4"
    # Default content type to application/json if data is provided, else none
    DEFAULT_CONTENT_TYPE=""
    if [ -n "$JSON_DATA" ]; then
        DEFAULT_CONTENT_TYPE="application/json"
    fi
    CONTENT_TYPE="${5:-$DEFAULT_CONTENT_TYPE}"

    URL="${API_BASE_URL}${ENDPOINT}"

    # Initialize curl arguments array
    CURL_ARGS=("-s" "-X" "${METHOD}")

    # Add Content-Type header if specified (and not "none")
    if [ -n "$CONTENT_TYPE" ] && [ "$CONTENT_TYPE" != "none" ]; then
        CURL_ARGS+=("-H" "Content-Type: ${CONTENT_TYPE}")
    fi

    # Add Authorization header if a token type is specified
    CURRENT_TOKEN=""
    if [ "$TOKEN_TYPE" == "admin" ]; then
        CURRENT_TOKEN="$ADMIN_TOKEN"
    elif [ "$TOKEN_TYPE" == "user" ]; then
        CURRENT_TOKEN="$USER_TOKEN"
    fi

    if [ -n "$CURRENT_TOKEN" ]; then
        CURL_ARGS+=("-H" "Authorization: Bearer ${CURRENT_TOKEN}")
    fi

    # Add data payload if provided
    if [ -n "$JSON_DATA" ]; then
        CURL_ARGS+=("-d" "$JSON_DATA")
    fi

    # Add URL as the last argument
    CURL_ARGS+=("${URL}")

    echo ""
    echo "--- Testing: ${METHOD} ${ENDPOINT} ---"
    if [ -n "$JSON_DATA" ]; then
        echo "Data: $JSON_DATA"
    fi

    # Construct a display string for the command (approximates actual execution)
    CMD_DISPLAY="curl"
    for arg in "${CURL_ARGS[@]}"; do
        if [[ "$arg" == *" "* ]]; then # Basic quoting for display if arg contains space
            CMD_DISPLAY+=" \"$arg\""
        else
            CMD_DISPLAY+=" $arg"
        fi
    done
    echo "Executing (approx): $CMD_DISPLAY"

    # Execute the curl command
    curl "${CURL_ARGS[@]}" | jq '.'
}

# --- Authentication Script ---

# 1. Admin Login (using email)
echo "--- Attempting Admin Login (using email) ---"
ADMIN_LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email": "'"${ADMIN_EMAIL}"'", "password": "'"${ADMIN_PASSWORD}"'"}' \
  "${API_BASE_URL}/auth/login/") # Assuming /auth/login/ is the JWT obtain pair view
echo "Admin Login Response: ${ADMIN_LOGIN_RESPONSE}" | jq '.'
ADMIN_TOKEN=$(echo "${ADMIN_LOGIN_RESPONSE}" | jq -r .access) # Adjusted to simple JWT response
ADMIN_REFRESH_TOKEN=$(echo "${ADMIN_LOGIN_RESPONSE}" | jq -r .refresh) # Adjusted

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
  echo "❌ FATAL: Admin login failed. Please check admin credentials (email, password) and server."
  exit 1
else
  echo "✅ Admin Token obtained."
fi

# 2. Register New User
echo "--- Attempting User Registration ---"
# RegisterSerializer likely still needs username for User model, email for uniqueness and login
REGISTER_PAYLOAD='{"email": "'"${NEW_USER_EMAIL}"'", "username": "'"${NEW_USER_USERNAME}"'", "password": "'"${NEW_USER_PASSWORD}"'", "password2": "'"${NEW_USER_PASSWORD}"'"}'
call_api "POST" "/auth/register/" "${REGISTER_PAYLOAD}" "none"

# 3. New User Login (using email)
echo "--- Attempting New User Login (using email) ---"
USER_LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"email": "'"${NEW_USER_EMAIL}"'", "password": "'"${NEW_USER_PASSWORD}"'"}' \
  "${API_BASE_URL}/auth/login/") # Assuming /auth/login/ is the JWT obtain pair view
echo "User Login Response: ${USER_LOGIN_RESPONSE}" | jq
USER_TOKEN=$(echo "${USER_LOGIN_RESPONSE}" | jq -r .access) # Adjusted
USER_REFRESH_TOKEN=$(echo "${USER_LOGIN_RESPONSE}" | jq -r .refresh) # Adjusted

if [ -z "$USER_TOKEN" ] || [ "$USER_TOKEN" == "null" ]; then
  echo "❌ FATAL: New user login failed. Registration might have failed or credentials mismatch."
else
  echo "✅ New User Token obtained."
fi

# 4. Verify Tokens
echo "--- Verifying Tokens ---"
if [ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ]; then
    call_api "POST" "/auth/verify/" '{"token": "'"${USER_TOKEN}"'"}' "none"
fi
if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
    call_api "POST" "/auth/verify/" '{"token": "'"${ADMIN_TOKEN}"'"}' "none"
fi

# 5. Refresh Token (User)
echo "--- Refreshing User Token ---"
if [ -n "$USER_REFRESH_TOKEN" ] && [ "$USER_REFRESH_TOKEN" != "null" ]; then
    REFRESH_RESPONSE_RAW=$(curl -s -X POST -H "Content-Type: application/json" \
        -d '{"refresh": "'"${USER_REFRESH_TOKEN}"'"}' \
        "${API_BASE_URL}/auth/refresh/")
    echo "Refresh Response: $REFRESH_RESPONSE_RAW" | jq
    NEW_USER_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE_RAW" | jq -r .access)
    if [ -n "$NEW_USER_ACCESS_TOKEN" ] && [ "$NEW_USER_ACCESS_TOKEN" != "null" ]; then
        USER_TOKEN=$NEW_USER_ACCESS_TOKEN # Update user token with the new one
        echo "✅ User token refreshed."
    else
        echo "⚠️ User token refresh failed or no new access token in response."
    fi
else
    echo "ℹ️ Skipping user token refresh as refresh token is not available."
fi


# --- User Info (Auth/Me) ---
echo "--- Testing UserInfoView (/auth/me/) ---"
# GET current user's info
if [ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ]; then
    USER_ME_RESPONSE_RAW=$(curl -s -X GET \
      -H "Authorization: Bearer ${USER_TOKEN}" \
      "${API_BASE_URL}/auth/me/")
    echo "$USER_ME_RESPONSE_RAW" | jq '.'
    NEW_USER_ID=$(echo "${USER_ME_RESPONSE_RAW}" | jq -r .data.id) # Assuming custom_api_response structure
    echo "Retrieved New User ID: $NEW_USER_ID"

    # Update current user's info
    USER_INFO_UPDATE_PAYLOAD='{"first_name": "Test", "last_name": "UserUpdatedByScript"}'
    call_api "PUT" "/auth/me/" "${USER_INFO_UPDATE_PAYLOAD}" "user"
else
    echo "ℹ️ Skipping /auth/me/ tests as USER_TOKEN is not available."
    NEW_USER_ID="" # Ensure it's empty if not fetched
fi


if [ -z "$NEW_USER_ID" ] || [ "$NEW_USER_ID" == "null" ]; then
    echo "⚠️ Could not retrieve new user's ID. Some permission tests might fail or be skipped."
fi

# --- Initial Data Creation (as Admin) ---

# Create a User Group
echo "--- Admin: Creating User Group ---"
UG_CREATE_PAYLOAD='{"name": "Test User Group '$(date +%s)'", "description": "A group for testing"}'
UG_CREATE_RESPONSE_RAW=$(curl -s -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "$UG_CREATE_PAYLOAD" \
  "${API_BASE_URL}/user-groups/")
echo "$UG_CREATE_RESPONSE_RAW" | jq '.'
TEST_USER_GROUP_ID=$(echo "$UG_CREATE_RESPONSE_RAW" | jq -r .data.id) # Assuming custom_api_response
if [ -z "$TEST_USER_GROUP_ID" ] || [ "$TEST_USER_GROUP_ID" == "null" ]; then echo "Failed to create user group or get ID."; else echo "User Group ID: $TEST_USER_GROUP_ID"; fi

# Create a Device Group
echo "--- Admin: Creating Device Group ---"
DG_CREATE_PAYLOAD='{"name": "Test Device Group '$(date +%s)'", "description": "A group for devices"}'
DG_CREATE_RESPONSE_RAW=$(curl -s -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "$DG_CREATE_PAYLOAD" \
  "${API_BASE_URL}/device-groups/")
echo "$DG_CREATE_RESPONSE_RAW" | jq '.'
TEST_DEVICE_GROUP_ID=$(echo "$DG_CREATE_RESPONSE_RAW" | jq -r .data.id) # Assuming custom_api_response
if [ -z "$TEST_DEVICE_GROUP_ID" ] || [ "$TEST_DEVICE_GROUP_ID" == "null" ]; then echo "Failed to create device group or get ID."; else echo "Device Group ID: $TEST_DEVICE_GROUP_ID"; fi

# Create a Device
echo "--- Admin: Creating a Device (using DeviceViewSet create) ---"
DEV_CREATE_PAYLOAD='{"device_ip": "192.168.1.254", "device_port": '$(shuf -i 10000-20000 -n 1)'}' # Random port
DEV_CREATE_RESPONSE_RAW=$(curl -s -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "$DEV_CREATE_PAYLOAD" \
    "${API_BASE_URL}/devices/")
echo "$DEV_CREATE_RESPONSE_RAW" | jq '.'
TEST_DEVICE_ID=$(echo "$DEV_CREATE_RESPONSE_RAW" | jq -r .data.id) # Assuming custom_api_response
ACTUAL_DEVICE_IDENTIFIER=$(echo "$DEV_CREATE_RESPONSE_RAW" | jq -r .data.device_identifier)

if [ -z "$TEST_DEVICE_ID" ] || [ "$TEST_DEVICE_ID" == "null" ]; then
    echo "Failed to create device or get ID."
else
    echo "Device ID: $TEST_DEVICE_ID, Identifier: $ACTUAL_DEVICE_IDENTIFIER"
    if [ -n "$ACTUAL_DEVICE_IDENTIFIER" ] && [ "$ACTUAL_DEVICE_IDENTIFIER" != "null" ]; then
        TEST_DEVICE_IDENTIFIER=$ACTUAL_DEVICE_IDENTIFIER
    fi
fi

# --- Permissions ---
echo "--- Testing Permissions ---"
if [ -n "$NEW_USER_ID" ] && [ "$NEW_USER_ID" != "null" ]; then
    echo "-- UserPermissionsView (/permissions/user/{user_id}/) --"
    call_api "GET" "/permissions/user/${NEW_USER_ID}/" "" "admin"
    if [ -n "$TEST_DEVICE_ID" ] && [ "$TEST_DEVICE_ID" != "null" ]; then
        USER_PERM_PAYLOAD='{"device_id": '${TEST_DEVICE_ID}', "permission_level": "usable"}'
        call_api "PUT" "/permissions/user/${NEW_USER_ID}/" "${USER_PERM_PAYLOAD}" "admin"
    else
        echo "ℹ️ Skipping user permission modification for device due to missing TEST_DEVICE_ID."
    fi
else
    echo "ℹ️ Skipping UserPermissionsView tests due to missing NEW_USER_ID."
fi

if [ -n "$TEST_USER_GROUP_ID" ] && [ "$TEST_USER_GROUP_ID" != "null" ]; then
    echo "-- GroupPermissionsView (/permissions/group/{group_id}/) --"
    call_api "GET" "/permissions/group/${TEST_USER_GROUP_ID}/" "" "admin"
    if [ -n "$TEST_DEVICE_ID" ] && [ "$TEST_DEVICE_ID" != "null" ]; then
        GROUP_PERM_PAYLOAD_DEV='{"device_id": '${TEST_DEVICE_ID}', "permission_level": "visible"}'
        call_api "PUT" "/permissions/group/${TEST_USER_GROUP_ID}/" "${GROUP_PERM_PAYLOAD_DEV}" "admin"
    else
        echo "ℹ️ Skipping group permission modification for device due to missing TEST_DEVICE_ID."
    fi
    if [ -n "$TEST_DEVICE_GROUP_ID" ] && [ "$TEST_DEVICE_GROUP_ID" != "null" ]; then
        GROUP_PERM_PAYLOAD_DG='{"device_group_id": '${TEST_DEVICE_GROUP_ID}', "permission_level": "visible"}'
        call_api "PUT" "/permissions/group/${TEST_USER_GROUP_ID}/" "${GROUP_PERM_PAYLOAD_DG}" "admin"
    else
        echo "ℹ️ Skipping group permission modification for device group due to missing TEST_DEVICE_GROUP_ID."
    fi
else
    echo "ℹ️ Skipping GroupPermissionsView tests due to missing TEST_USER_GROUP_ID."
fi

# --- User Groups (UserGroupViewSet) ---
echo "--- Testing UserGroupViewSet (/user-groups/) ---"
call_api "GET" "/user-groups/" "" "user"
call_api "GET" "/user-groups/" "" "admin"
if [ -n "$TEST_USER_GROUP_ID" ] && [ "$TEST_USER_GROUP_ID" != "null" ]; then
    call_api "GET" "/user-groups/${TEST_USER_GROUP_ID}/" "" "admin"
    UG_UPDATE_PAYLOAD='{"name": "Test User Group Updated '$(date +%s)'", "description": "Updated desc"}'
    call_api "PUT" "/user-groups/${TEST_USER_GROUP_ID}/" "${UG_UPDATE_PAYLOAD}" "admin"
    if [ -n "$NEW_USER_ID" ] && [ "$NEW_USER_ID" != "null" ]; then
        UG_ADD_MEMBER_PAYLOAD='{"user_id": '${NEW_USER_ID}'}'
        call_api "POST" "/user-groups/${TEST_USER_GROUP_ID}/members/" "${UG_ADD_MEMBER_PAYLOAD}" "admin"
        call_api "DELETE" "/user-groups/${TEST_USER_GROUP_ID}/members/${NEW_USER_ID}/" "" "admin"
    else
        echo "ℹ️ Skipping add/remove member from user group due to missing NEW_USER_ID."
    fi
else
    echo "ℹ️ Skipping UserGroup Retrieve, Update, Member tests due to missing TEST_USER_GROUP_ID."
fi

# --- Device Groups (DeviceGroupViewSet) ---
echo "--- Testing DeviceGroupViewSet (/device-groups/) ---"
call_api "GET" "/device-groups/" "" "user"
call_api "GET" "/device-groups/" "" "admin"
if [ -n "$TEST_DEVICE_GROUP_ID" ] && [ "$TEST_DEVICE_GROUP_ID" != "null" ]; then
    call_api "GET" "/device-groups/${TEST_DEVICE_GROUP_ID}/" "" "admin"
    DG_UPDATE_PAYLOAD='{"name": "Test Device Group Updated '$(date +%s)'", "description": "Updated desc"}'
    call_api "PUT" "/device-groups/${TEST_DEVICE_GROUP_ID}/" "${DG_UPDATE_PAYLOAD}" "admin"
    if [ -n "$TEST_DEVICE_ID" ] && [ "$TEST_DEVICE_ID" != "null" ]; then
        DG_ADD_DEVICE_PAYLOAD='{"device_id": '${TEST_DEVICE_ID}'}'
        call_api "POST" "/device-groups/${TEST_DEVICE_GROUP_ID}/devices/" "${DG_ADD_DEVICE_PAYLOAD}" "admin"
        call_api "DELETE" "/device-groups/${TEST_DEVICE_GROUP_ID}/devices/${TEST_DEVICE_ID}/" "" "admin"
    else
        echo "ℹ️ Skipping add/remove device from device group due to missing TEST_DEVICE_ID."
    fi
else
    echo "ℹ️ Skipping DeviceGroup Retrieve, Update, Member tests due to missing TEST_DEVICE_GROUP_ID."
fi


# --- Devices (DeviceViewSet & related) ---
echo "--- Testing DeviceViewSet (/devices/) & related views ---"
call_api "GET" "/devices/discover/" "" "admin"
call_api "GET" "/devices/" "" "user"
call_api "GET" "/devices/" "" "admin"

if [ -n "$TEST_DEVICE_ID" ] && [ "$TEST_DEVICE_ID" != "null" ]; then
    echo "Attempting to retrieve device as USER (depends on permissions)"
    call_api "GET" "/devices/${TEST_DEVICE_ID}/" "" "user"
    call_api "GET" "/devices/${TEST_DEVICE_ID}/" "" "admin"

    DEV_UPDATE_PAYLOAD_DIRECT='{"name": "Updated Device Name '$(date +%s)'", "location": "New Room", "status": "online"}'
    call_api "PUT" "/devices/${TEST_DEVICE_ID}/" "${DEV_UPDATE_PAYLOAD_DIRECT}" "admin"
    DEV_UPDATE_PAYLOAD_DICT='{"device_info": {"description": "This is a test note via dict update"}}'
    call_api "PUT" "/devices/${TEST_DEVICE_ID}/" "${DEV_UPDATE_PAYLOAD_DICT}" "admin"
    DEV_PATCH_PAYLOAD='{"status": "maintenance"}'
    call_api "PATCH" "/devices/${TEST_DEVICE_ID}/" "${DEV_PATCH_PAYLOAD}" "admin"

    echo "Attempting to control device as USER (depends on CanControlDevice permission)"
    CONTROL_PAYLOAD_ON='{"action": "turn_on"}'
    call_api "POST" "/devices/${TEST_DEVICE_ID}/control/" "${CONTROL_PAYLOAD_ON}" "user"
    CONTROL_PAYLOAD_OFF='{"action": "turn_off"}'
    call_api "POST" "/devices/${TEST_DEVICE_ID}/control/" "${CONTROL_PAYLOAD_OFF}" "user"
    # CONTROL_PAYLOAD_TEMP='{"action": "set_temperature", "parameters": {"temperature": 25}}' # Requires device_type setup

    echo "Attempting to get device detail as USER (depends on CanMonitorDevice permission)"
    call_api "GET" "/devices/${TEST_DEVICE_ID}/detail/" "" "user"
    call_api "GET" "/devices/${TEST_DEVICE_ID}/detail/" "" "admin"
else
    echo "ℹ️ Skipping Device retrieve, update, control, detail tests due to missing TEST_DEVICE_ID."
fi

call_api "GET" "/devices/overview/" "" "user"
call_api "GET" "/devices/overview/" "" "admin"

HEARTBEAT_PAYLOAD='{"device_identifier": "'"${TEST_DEVICE_IDENTIFIER}"'", "status": "online", "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'", "data": {"current_power_consumption": 10.5}}'
if [ -n "$TEST_DEVICE_IDENTIFIER" ] && [ "$TEST_DEVICE_IDENTIFIER" != "null" ]; then
    call_api "POST" "/devices/heartbeat/" "${HEARTBEAT_PAYLOAD}" "none"
else
    echo "ℹ️ Skipping heartbeat test due to missing TEST_DEVICE_IDENTIFIER."
fi

# --- Cleanup (Optional - Delete created resources as Admin) ---
echo "--- Optional Cleanup (Delete created resources) ---"

if [ -n "$TEST_DEVICE_ID" ] && [ "$TEST_DEVICE_ID" != "null" ]; then
     call_api "DELETE" "/devices/${TEST_DEVICE_ID}/" "" "admin"
else
    echo "ℹ️ Skipping device deletion."
fi

if [ -n "$TEST_DEVICE_GROUP_ID" ] && [ "$TEST_DEVICE_GROUP_ID" != "null" ]; then
     call_api "DELETE" "/device-groups/${TEST_DEVICE_GROUP_ID}/" "" "admin"
else
    echo "ℹ️ Skipping device group deletion."
fi

if [ -n "$TEST_USER_GROUP_ID" ] && [ "$TEST_USER_GROUP_ID" != "null" ]; then
     call_api "DELETE" "/user-groups/${TEST_USER_GROUP_ID}/" "" "admin"
else
    echo "ℹ️ Skipping user group deletion."
fi

echo ""
echo "--- All Tests Completed ---"