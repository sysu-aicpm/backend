# 1. 登录并获取 Token
LOGIN_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"email": "ykx@abc.com", "password": "ykx"}' \
  http://127.0.0.1:8000/api/v1/auth/login/)

# 2. 从响应中提取 Access Token (需要 jq 工具)
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r .access)

# 如果没有 jq，你需要手动从 LOGIN_RESPONSE 的输出中复制 access token
# echo $LOGIN_RESPONSE # 然后手动复制 access token

# 检查 ACCESS_TOKEN 是否获取成功
echo "Access Token: $ACCESS_TOKEN"

# 如果 ACCESS_TOKEN 为空或 "null"，请检查登录凭据和登录接口的响应
if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
  echo "错误：未能获取 Access Token。请检查你的用户名和密码以及登录接口的响应。"
  echo "登录响应内容: $LOGIN_RESPONSE"
  exit 1
fi

curl -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/api/v1/auth/me/ | jq

curl -X PUT \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"first_name": "新的名字", "last_name": "新的姓氏"}' \
  http://127.0.0.1:8000/api/v1/auth/me/ | jq