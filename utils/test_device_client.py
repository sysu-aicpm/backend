"""
设备客户端测试脚本
用于测试与virtual-device的通信
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 设置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smart_home.settings')
django.setup()

from utils.device_client import get_device_client, close_device_client
import asyncio


def test_device_query():
    """测试设备查询"""
    print("=== 测试设备查询 ===")
    
    client = get_device_client()
    
    # 测试查询设备信息
    keys = ["device_id", "device_type", "power", "status", "temperature", "brightness", "locked", "recording"]
    result = client.query_device("localhost", 5000, keys)
    
    if result.success:
        print("✅ 设备查询成功:")
        print(f"   数据: {result.data}")
    else:
        print("❌ 设备查询失败:")
        print(f"   错误: {result.error}")
        print(f"   状态码: {result.status_code}")


def test_device_control():
    """测试设备控制"""
    print("\n=== 测试设备控制 ===")

    client = get_device_client()

    # 首先查询设备类型
    query_result = client.query_device("localhost", 5000, ["device_type"])
    if not query_result.success:
        print("❌ 无法查询设备类型，跳过控制测试")
        return

    device_type = query_result.data.get("device_type")
    print(f"   检测到设备类型: {device_type}")

    # 根据设备类型选择合适的控制命令
    if device_type == "refrigerator":
        # 冰箱：设置温度
        result = client.control_device("localhost", 5000, "set_temperature", {"temperature": 2})
        action_desc = "设置温度为2℃"
    elif device_type == "light":
        # 灯：开关控制
        result = client.control_device("localhost", 5000, "switch", {"state": "on"})
        action_desc = "开灯"
    elif device_type == "lock":
        # 锁：解锁
        result = client.control_device("localhost", 5000, "set_lock", {"state": "unlock"})
        action_desc = "解锁"
    elif device_type == "camera":
        # 摄像头：开始录制
        result = client.control_device("localhost", 5000, "set_recording", {"state": "start"})
        action_desc = "开始录制"
    else:
        print(f"   ⚠️ 未知设备类型: {device_type}")
        return

    if result.success:
        control_success = result.data.get("success", False)
        if control_success:
            print(f"✅ 设备控制成功: {action_desc}")
        else:
            print(f"⚠️ 设备控制命令发送成功，但设备返回失败: {action_desc}")
        print(f"   数据: {result.data}")
    else:
        print("❌ 设备控制失败:")
        print(f"   错误: {result.error}")
        print(f"   状态码: {result.status_code}")


def test_controller_apis():
    """测试控制器API"""
    print("\n=== 测试控制器API ===")
    
    client = get_device_client()
    
    # 测试获取设备列表
    print("1. 获取设备列表:")
    result = client.list_devices_from_controller()
    if result.success:
        print(f"   ✅ 成功，设备数量: {len(result.data)}")
        for device in result.data:
            print(f"      - {device.get('device_id')}: {device.get('device_type')} ({device.get('status')})")
    else:
        print(f"   ❌ 失败: {result.error}")
    
    # 测试获取事件历史
    print("\n2. 获取事件历史:")
    result = client.get_events_from_controller()
    if result.success:
        print(f"   ✅ 成功，事件数量: {len(result.data)}")
        for event in result.data[-3:]:  # 显示最近3个事件
            print(f"      - {event.get('device_id')}: {event.get('event_type')}")
    else:
        print(f"   ❌ 失败: {result.error}")


async def test_async_operations():
    """测试异步操作"""
    print("\n=== 测试异步操作 ===")
    
    client = get_device_client()
    
    # 异步查询设备
    print("1. 异步查询设备:")
    keys = ["device_id", "device_type", "status"]
    result = await client.query_device_async("localhost", 5000, keys)
    
    if result.success:
        print("   ✅ 异步查询成功:")
        print(f"      数据: {result.data}")
    else:
        print("   ❌ 异步查询失败:")
        print(f"      错误: {result.error}")
    
    # 异步控制设备 - 根据设备类型选择合适的命令
    print("\n2. 异步控制设备:")
    device_type = result.data.get("device_type") if result.success else "unknown"

    if device_type == "refrigerator":
        control_result = await client.control_device_async(
            "localhost", 5000, "set_temperature", {"temperature": 3}
        )
        action_desc = "设置温度为3℃"
    else:
        control_result = await client.control_device_async(
            "localhost", 5000, "switch", {"state": "off"}
        )
        action_desc = "关闭设备"

    if control_result.success:
        control_success = control_result.data.get("success", False)
        if control_success:
            print(f"   ✅ 异步控制成功: {action_desc}")
        else:
            print(f"   ⚠️ 异步控制命令发送成功，但设备返回失败: {action_desc}")
        print(f"      数据: {control_result.data}")
    else:
        print("   ❌ 异步控制失败:")
        print(f"      错误: {control_result.error}")


def main():
    """主测试函数"""
    print("🚀 开始测试设备客户端...")
    print("📝 请确保virtual-device和controller正在运行")
    print("   - virtual-device: http://localhost:5000")
    print("   - controller: http://localhost:8000")
    print()

    try:
        # 同步测试
        test_device_query()
        test_device_control()
        test_controller_apis()

        # 异步测试
        print("\n" + "="*50)
        asyncio.run(test_async_operations())

        print("\n🎉 测试完成!")

    except KeyboardInterrupt:
        print("\n⚠️ 测试被用户中断")
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
    finally:
        # 清理资源
        close_device_client()
        print("🧹 资源清理完成")


if __name__ == "__main__":
    main()
