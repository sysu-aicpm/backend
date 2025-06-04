"""
设备通信客户端
与virtual-device进行HTTP通信的客户端实现
"""
import httpx
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


@dataclass
class DeviceResponse:
    """设备响应数据结构"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None


class DeviceClient:
    """设备通信客户端"""
    
    def __init__(self, timeout: float = 10.0, max_retries: int = 3):
        """
        初始化设备客户端
        
        Args:
            timeout: 请求超时时间（秒）
            max_retries: 最大重试次数
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.device_settings = getattr(settings, 'DEVICE_SETTINGS', {})
        
        # 创建HTTP客户端
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
        
        # 创建异步HTTP客户端
        self.async_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
    
    def __del__(self):
        """清理资源"""
        try:
            self.client.close()
        except Exception:
            pass

    async def close_async(self):
        """异步关闭客户端"""
        try:
            await self.async_client.aclose()
        except Exception:
            pass
    
    def _get_device_url(self, device_ip: str, device_port: int) -> str:
        """构建设备URL"""
        return f"http://{device_ip}:{device_port}"
    
    def _get_controller_url(self) -> str:
        """获取控制器URL"""
        host = self.device_settings.get('DEVICE_CONTROLLER_HOST', 'localhost')
        port = self.device_settings.get('DEVICE_CONTROLLER_PORT', 8000)
        return f"http://{host}:{port}"
    
    def _handle_response(self, response: httpx.Response) -> DeviceResponse:
        """处理HTTP响应"""
        try:
            if response.status_code == 200:
                data = response.json() if response.content else {}
                return DeviceResponse(success=True, data=data, status_code=response.status_code)
            else:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get('error', f'HTTP {response.status_code}')
                return DeviceResponse(
                    success=False, 
                    error=error_msg, 
                    status_code=response.status_code,
                    data=error_data
                )
        except Exception as e:
            logger.error(f"响应处理失败: {e}")
            return DeviceResponse(
                success=False, 
                error=f"响应解析失败: {str(e)}", 
                status_code=response.status_code
            )
    
    def query_device(self, device_ip: str, device_port: int, keys: List[str]) -> DeviceResponse:
        """
        查询设备信息
        
        Args:
            device_ip: 设备IP地址
            device_port: 设备端口
            keys: 要查询的字段列表
            
        Returns:
            DeviceResponse: 查询结果
        """
        url = f"{self._get_device_url(device_ip, device_port)}/query"
        payload = {"keys": keys}
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"查询设备 {device_ip}:{device_port}, 尝试 {attempt + 1}/{self.max_retries}")
                response = self.client.post(url, json=payload)
                result = self._handle_response(response)
                
                if result.success:
                    logger.info(f"设备查询成功: {device_ip}:{device_port}")
                    return result
                elif response.status_code >= 500 and attempt < self.max_retries - 1:
                    # 服务器错误时重试
                    logger.warning(f"服务器错误，准备重试: {result.error}")
                    continue
                else:
                    return result
                    
            except httpx.TimeoutException:
                error_msg = f"设备查询超时: {device_ip}:{device_port}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
            except httpx.ConnectError:
                error_msg = f"无法连接到设备: {device_ip}:{device_port}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
            except Exception as e:
                error_msg = f"设备查询异常: {str(e)}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
        
        return DeviceResponse(success=False, error="查询失败，已达到最大重试次数")
    
    def control_device(self, device_ip: str, device_port: int, action: str, params: Dict[str, Any] = None) -> DeviceResponse:
        """
        控制设备
        
        Args:
            device_ip: 设备IP地址
            device_port: 设备端口
            action: 控制动作
            params: 控制参数
            
        Returns:
            DeviceResponse: 控制结果
        """
        url = f"{self._get_device_url(device_ip, device_port)}/control"
        payload = {
            "action": action,
            "params": params or {}
        }
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"控制设备 {device_ip}:{device_port}, 动作: {action}")
                response = self.client.post(url, json=payload)
                result = self._handle_response(response)
                
                if result.success:
                    logger.info(f"设备控制成功: {device_ip}:{device_port}, 动作: {action}")
                    return result
                elif response.status_code >= 500 and attempt < self.max_retries - 1:
                    logger.warning(f"服务器错误，准备重试: {result.error}")
                    continue
                else:
                    return result
                    
            except httpx.TimeoutException:
                error_msg = f"设备控制超时: {device_ip}:{device_port}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
            except httpx.ConnectError:
                error_msg = f"无法连接到设备: {device_ip}:{device_port}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
            except Exception as e:
                error_msg = f"设备控制异常: {str(e)}"
                logger.error(error_msg)
                if attempt == self.max_retries - 1:
                    return DeviceResponse(success=False, error=error_msg)
        
        return DeviceResponse(success=False, error="控制失败，已达到最大重试次数")

    def list_devices_from_controller(self) -> DeviceResponse:
        """
        从控制器获取设备列表

        Returns:
            DeviceResponse: 设备列表
        """
        url = f"{self._get_controller_url()}/devices"

        try:
            logger.info("从控制器获取设备列表")
            response = self.client.get(url)
            result = self._handle_response(response)

            if result.success:
                logger.info(f"获取到 {len(result.data)} 个设备")

            return result

        except httpx.TimeoutException:
            error_msg = "控制器连接超时"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except httpx.ConnectError:
            error_msg = "无法连接到控制器"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except Exception as e:
            error_msg = f"获取设备列表异常: {str(e)}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)

    def get_device_from_controller(self, device_id: str) -> DeviceResponse:
        """
        从控制器获取特定设备信息

        Args:
            device_id: 设备ID

        Returns:
            DeviceResponse: 设备信息
        """
        url = f"{self._get_controller_url()}/device/{device_id}"

        try:
            logger.info(f"从控制器获取设备信息: {device_id}")
            response = self.client.get(url)
            result = self._handle_response(response)

            if result.success:
                logger.info(f"获取设备信息成功: {device_id}")

            return result

        except httpx.TimeoutException:
            error_msg = f"获取设备信息超时: {device_id}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except httpx.ConnectError:
            error_msg = "无法连接到控制器"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except Exception as e:
            error_msg = f"获取设备信息异常: {str(e)}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)

    def get_events_from_controller(self) -> DeviceResponse:
        """
        从控制器获取事件历史

        Returns:
            DeviceResponse: 事件列表
        """
        url = f"{self._get_controller_url()}/events"

        try:
            logger.info("从控制器获取事件历史")
            response = self.client.get(url)
            result = self._handle_response(response)

            if result.success:
                logger.info(f"获取到 {len(result.data)} 个事件")

            return result

        except httpx.TimeoutException:
            error_msg = "获取事件历史超时"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except httpx.ConnectError:
            error_msg = "无法连接到控制器"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except Exception as e:
            error_msg = f"获取事件历史异常: {str(e)}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)

    async def query_device_async(self, device_ip: str, device_port: int, keys: List[str]) -> DeviceResponse:
        """
        异步查询设备信息

        Args:
            device_ip: 设备IP地址
            device_port: 设备端口
            keys: 要查询的字段列表

        Returns:
            DeviceResponse: 查询结果
        """
        url = f"{self._get_device_url(device_ip, device_port)}/query"
        payload = {"keys": keys}

        try:
            logger.info(f"异步查询设备 {device_ip}:{device_port}")
            response = await self.async_client.post(url, json=payload)
            result = self._handle_response(response)

            if result.success:
                logger.info(f"异步设备查询成功: {device_ip}:{device_port}")

            return result

        except httpx.TimeoutException:
            error_msg = f"异步设备查询超时: {device_ip}:{device_port}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except httpx.ConnectError:
            error_msg = f"无法连接到设备: {device_ip}:{device_port}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except Exception as e:
            error_msg = f"异步设备查询异常: {str(e)}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)

    async def control_device_async(self, device_ip: str, device_port: int, action: str, params: Dict[str, Any] = None) -> DeviceResponse:
        """
        异步控制设备

        Args:
            device_ip: 设备IP地址
            device_port: 设备端口
            action: 控制动作
            params: 控制参数

        Returns:
            DeviceResponse: 控制结果
        """
        url = f"{self._get_device_url(device_ip, device_port)}/control"
        payload = {
            "action": action,
            "params": params or {}
        }

        try:
            logger.info(f"异步控制设备 {device_ip}:{device_port}, 动作: {action}")
            response = await self.async_client.post(url, json=payload)
            result = self._handle_response(response)

            if result.success:
                logger.info(f"异步设备控制成功: {device_ip}:{device_port}, 动作: {action}")

            return result

        except httpx.TimeoutException:
            error_msg = f"异步设备控制超时: {device_ip}:{device_port}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except httpx.ConnectError:
            error_msg = f"无法连接到设备: {device_ip}:{device_port}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)
        except Exception as e:
            error_msg = f"异步设备控制异常: {str(e)}"
            logger.error(error_msg)
            return DeviceResponse(success=False, error=error_msg)


# 全局设备客户端实例
DEVICE_CLIENT_INSTANCE = None


def get_device_client() -> DeviceClient:
    """获取全局设备客户端实例"""
    global DEVICE_CLIENT_INSTANCE
    if DEVICE_CLIENT_INSTANCE is None:
        DEVICE_CLIENT_INSTANCE = DeviceClient()
    return DEVICE_CLIENT_INSTANCE


def close_device_client():
    """关闭全局设备客户端"""
    global DEVICE_CLIENT_INSTANCE
    if DEVICE_CLIENT_INSTANCE is not None:
        DEVICE_CLIENT_INSTANCE.client.close()
        DEVICE_CLIENT_INSTANCE = None


async def close_device_client_async():
    """异步关闭全局设备客户端"""
    global DEVICE_CLIENT_INSTANCE
    if DEVICE_CLIENT_INSTANCE is not None:
        DEVICE_CLIENT_INSTANCE.client.close()
        await DEVICE_CLIENT_INSTANCE.close_async()
        DEVICE_CLIENT_INSTANCE = None
