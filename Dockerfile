# 使用官方 Python 3.11 镜像作为基础镜像
FROM python:3.11

# 设置工作目录
WORKDIR /app

# 复制项目文件
COPY . /app/

# 创建 logs 目录和 django.log 文件
RUN mkdir -p logs && touch logs/django.log

# 安装 Python 依赖
RUN pip install --no-cache-dir django djangorestframework mysqlclient djangorestframework-simplejwt django-cors-headers
# (如果有 requirements.txt）
RUN pip install --no-cache-dir -r requirements.txt

# 设置启动脚本权限
RUN chmod +x /app/entrypoint.sh

# 暴露 Django 默认端口
EXPOSE 8000

# 设置环境变量
ENV DJANGO_SUPERUSER_USERNAME=admin 
ENV DJANGO_SUPERUSER_PASSWORD=sysu-aicpm2025
ENV DJANGO_SUPERUSER_EMAIL=admin@example.com

ENV DB_ENGINE=django.db.backends.mysql
ENV DB_NAME=sysu-aicpm2025
ENV DB_USER=root
ENV DB_PASSWORD=sysu-aicpm2025
# 在容器环境中，使用服务名作为主机名
ENV DB_HOST=aicpm-sql
ENV DB_PORT=3306

# 启动命令（运行脚本）
ENTRYPOINT ["/app/entrypoint.sh"]
