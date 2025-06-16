#!/bin/bash

set -e  # 出错时停止执行
printenv
sleep 2
# 进入项目目录
cd /app

# 设置 Django 环境变量（根据你的项目名称修改）
export DJANGO_SETTINGS_MODULE=smart_home.settings

# 执行数据库迁移
echo "Apply database migrations..."
python manage.py makemigrations api --noinput
python manage.py migrate --noinput

# 先创建管理员
python manage.py createsuperuser --noinput

# 收集静态文件（用于部署）
echo "Collect static files..."
python manage.py collectstatic --noinput

# 启动 Gunicorn（使用你项目的 wsgi.py 文件路径）
echo "Starting Gunicorn..."
exec gunicorn --bind :8000 --workers 3 --timeout 120 smart_home.wsgi:application
