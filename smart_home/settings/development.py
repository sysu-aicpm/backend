"""
开发环境配置
"""
from .base import *

# 开发环境特定配置
DEBUG = True

# 开发环境允许的主机
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# 开发环境中间件（添加调试工具栏）
MIDDLEWARE += [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
]

# 开发环境应用（添加调试工具栏）
INSTALLED_APPS += [
    'debug_toolbar',
]

# 调试工具栏配置
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

# 开发环境CORS配置（允许所有来源）
CORS_ALLOW_ALL_ORIGINS = True

# 开发环境数据库配置（可以使用SQLite进行快速开发）
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }

# 开发环境日志配置（更详细的日志）
LOGGING['loggers']['django']['level'] = 'DEBUG'
LOGGING['loggers']['api']['level'] = 'DEBUG'

# 开发环境缓存配置（使用内存缓存）
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# 开发环境邮件配置（控制台输出）
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# 开发环境静态文件配置
STATICFILES_DIRS += [
    BASE_DIR / 'api' / 'static',
]
