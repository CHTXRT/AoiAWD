"""
Agent 事件监听服务
接收来自靶机C探针的文件变更事件
"""

import socket
import threading
import json
import logging
import time
from typing import Callable, Dict, List, Optional
from queue import Queue, Empty
from collections import defaultdict

logger = logging.getLogger('AgentListener')


class AgentListener:
    """
    TCP服务器，接收Agent上报的文件事件
    支持批量事件和心跳检测
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8024):
        self.host = host
        self.port = port
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        self.server_socket: Optional[socket.socket] = None
        
        # 事件队列: 供消费者使用
        self.event_queue: Queue = Queue(maxsize=10000)
        
        # Agent心跳记录: {(ip,port): last_heartbeat_time}
        self.agent_heartbeats: Dict[tuple, float] = {}
        self.heartbeat_lock = threading.Lock()
        
        # 回调函数列表: 支持多个订阅者
        self._callbacks: List[Callable[[str, int, dict], None]] = []
        self._callback_lock = threading.Lock()
        
        # WebSocket 引用
        self.socketio = None
        
        # 统计信息
        self.stats = {
            'total_events': 0,
            'total_heartbeats': 0,
            'start_time': None
        }
    
    def subscribe(self, callback: Callable[[str, int, dict], None]):
        """订阅文件事件"""
        with self._callback_lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
                logger.info(f"New subscriber added, total: {len(self._callbacks)}")
    
    def unsubscribe(self, callback: Callable[[str, int, dict], None]):
        """取消订阅"""
        with self._callback_lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
    
    def _notify_subscribers(self, ip: str, port: int, event: dict):
        """通知所有订阅者"""
        with self._callback_lock:
            callbacks = self._callbacks.copy()
        
        for callback in callbacks:
            try:
                callback(ip, port, event)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def start(self) -> bool:
        """启动监听服务"""
        if self.running:
            return True
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.server_socket.settimeout(1.0)  # 允许定期检查running标志
            
            self.running = True
            self.stats['start_time'] = time.time()
            
            self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.server_thread.start()
            
            logger.info(f"Agent listener started on {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start listener: {e}")
            return False
    
    def stop(self):
        """停止监听服务"""
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except: pass
        
        if self.server_thread:
            self.server_thread.join(timeout=3)
        
        logger.info("Agent listener stopped")
    
    def _listen_loop(self):
        """主监听循环"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                # 新线程处理每个连接
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                # Socket已关闭
                break
            except Exception as e:
                logger.error(f"Accept error: {e}")
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """处理单个Agent连接"""
        client_ip = addr[0]
        logger.info(f"[AgentListener] New connection from {client_ip}")
        
        try:
            conn.settimeout(5.0)
            
            # 读取数据（Agent发送的是单行JSON）
            data = b""
            while b'\n' not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:  # 防止恶意大数据
                    break
            
            if not data:
                logger.warning(f"[AgentListener] No data from {client_ip}")
                return
            
            logger.info(f"[AgentListener] Raw data from {client_ip}: {data[:200]}")
            
            # 解析JSON
            try:
                msg = json.loads(data.decode('utf-8', errors='ignore').strip())
                msg['_source_ip'] = client_ip
                logger.info(f"[AgentListener] Parsed message from {client_ip}: type={msg.get('type')}")
                self._process_message(client_ip, msg)
            except json.JSONDecodeError as e:
                logger.warning(f"[AgentListener] Invalid JSON from {client_ip}: {e}, data: {data[:100]}")
                
        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"Connection handler error: {e}")
        finally:
            try:
                conn.close()
            except: pass
    
    def _process_message(self, ip: str, msg: dict):
        """处理Agent消息"""
        msg_type = msg.get('type')
        logger.info(f"[AgentListener] Processing message type: {msg_type} from {ip}")
        
        if msg_type == 'file':
            # 单文件事件（旧版Agent兼容）
            self._handle_file_event(ip, msg)
            
        elif msg_type == 'batch':
            # 批量事件
            events = msg.get('events', [])
            logger.info(f"[AgentListener] Batch message with {len(events)} events from {ip}")
            for ev in events:
                ev['_source_ip'] = ip
                self._handle_file_event(ip, ev)
            
            if events:
                logger.info(f"[{ip}] Processed batch: {len(events)} events")
                
        elif msg_type == 'heartbeat':
            # 心跳
            logger.info(f"[AgentListener] Heartbeat from {ip}")
            self._handle_heartbeat(ip, msg)
            
        else:
            logger.warning(f"[AgentListener] Unknown message type from {ip}: {msg_type}")
    
    def _handle_file_event(self, ip: str, event: dict):
        """处理文件事件"""
        path = event.get('path', '')
        mask = event.get('mask', 0)
        timestamp = event.get('time', time.time())
        
        logger.info(f"[AgentListener] File event from {ip}: {path} (mask:{mask})")
        
        # 只处理.php文件
        if not path.endswith('.php'):
            logger.debug(f"[AgentListener] Ignoring non-PHP file: {path}")
            return
        
        # 构造标准化事件
        file_event = {
            'type': 'file',
            'source_ip': ip,
            'path': path,
            'mask': mask,
            'timestamp': timestamp,
            'event_time': time.time()
        }
        
        # 放入队列（供消费者拉取）
        try:
            self.event_queue.put_nowait(file_event)
            self.stats['total_events'] += 1
        except:
            logger.warning("Event queue full, dropping event")
        
        # 通知所有订阅者（推模式）
        self._notify_subscribers(ip, 22, file_event)
        
        logger.debug(f"[File] {ip}: {path} (mask:{mask})")
    
    def _handle_heartbeat(self, ip: str, msg: dict):
        """处理心跳"""
        watch_dir = msg.get('dir', '')
        
        key = (ip, 22)  # 默认SSH端口
        with self.heartbeat_lock:
            self.agent_heartbeats[key] = time.time()
        
        self.stats['total_heartbeats'] += 1
        logger.debug(f"[Heartbeat] {ip}: {watch_dir}")
        
        # WebSocket 推送心跳状态（用于前端呼吸灯）
        if self.socketio:
            try:
                self.socketio.emit('agent_heartbeat', {
                    'ip': ip,
                    'port': 22,
                    'status': 'online',
                    'timestamp': time.time()
                })
            except:
                pass
    
    def get_events(self, timeout: float = 0) -> List[dict]:
        """
        获取待处理的事件
        
        Args:
            timeout: 等待超时（秒），0表示非阻塞
        
        Returns:
            事件列表
        """
        events = []
        deadline = time.time() + timeout if timeout > 0 else 0
        
        while True:
            try:
                remaining = max(0, deadline - time.time()) if deadline else 0
                if deadline and remaining <= 0:
                    break
                
                event = self.event_queue.get(block=timeout > 0, timeout=remaining or None)
                events.append(event)
                
                # 批量获取，最多100个
                if len(events) >= 100:
                    break
                    
            except Empty:
                break
        
        return events
    
    def get_agent_health(self, ip: str, port: int = 22) -> dict:
        """获取Agent健康状态"""
        key = (ip, port)
        
        with self.heartbeat_lock:
            last_beat = self.agent_heartbeats.get(key, 0)
        
        now = time.time()
        silence = now - last_beat
        
        # 45秒无心跳认为失联（心跳间隔30秒）
        is_alive = silence < 45 and last_beat > 0
        
        return {
            'is_alive': is_alive,
            'last_heartbeat': last_beat,
            'silence_seconds': silence,
            'status': 'online' if is_alive else 'offline'
        }
    
    def get_all_agents_health(self) -> Dict[tuple, dict]:
        """获取所有Agent的健康状态"""
        result = {}
        with self.heartbeat_lock:
            keys = list(self.agent_heartbeats.keys())
        
        for key in keys:
            result[key] = self.get_agent_health(key[0], key[1])
        
        return result
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'queue_size': self.event_queue.qsize(),
            'is_running': self.running,
            'address': f"{self.host}:{self.port}"
        }
    
    def clear_events(self):
        """清空事件队列"""
        while not self.event_queue.empty():
            try:
                self.event_queue.get_nowait()
            except:
                break
        logger.info("Event queue cleared")
