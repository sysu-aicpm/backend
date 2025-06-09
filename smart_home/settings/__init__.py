import os

# 默认使用开发环境配置
enviroment = os.getenv('ENVIROMENT', 'development')

if enviroment == 'production' :
  from .production import *
else: 
  from .development import *