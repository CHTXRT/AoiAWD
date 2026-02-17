"""
文件监控服务 - 基于AgentListener的集成版本
不再独立监听端口，复用AgentListener的数据
"""
import threading
import json
import time
import logging
import os

logger = logging.getLogger('Monitor')
logger.setLevel(logging.INFO)


class MonitorService:
    """
    文件监控服务（Agent事件消费者）
    复用 AgentListener 的数据，提供规则检测和告警
    """
    
    # 可疑脚本扩展名
    SUSPICIOUS_EXTS = ['.php', '.py', '.pl', '.sh', '.jsp', '.asp', '.aspx']
    
    # 危险命令特征
    DANGEROUS_CMDS = ['nc ', 'netcat', 'bash -i', 'zsh -i', 'curl ', 'wget ', 'lynx ', 
                      'python -c', 'perl -e', 'ruby -e', 'mkfifo', '/dev/tcp/']
    
    def __init__(self, connection_manager, target_manager, agent_listener=None, agent_deployer=None):
        self.cm = connection_manager
        self.tm = target_manager
        self.agent_listener = agent_listener
        self.agent_deployer = agent_deployer  # 用于实际部署Agent
        
        self.running = False
        self.logs = []  # 内存日志
        self.alert_lock = threading.Lock()
        self.process_thread = None
        
        # 告警统计
        self.alert_count = 0
        self.last_alert_time = 0
        
    def start(self):
        """启动监控服务（订阅AgentListener事件）"""
        if self.running:
            return
        
        self.running = True
        
        # 订阅Agent事件（推模式）
        if self.agent_listener:
            self.agent_listener.subscribe(self._handle_event)
            logger.info("MonitorService subscribed to agent events")
        else:
            # 回退到拉取模式
            self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
            self.process_thread.start()
            logger.info("MonitorService started (pull mode)")

    def stop(self):
        """停止监控服务"""
        self.running = False
        # 取消订阅
        if self.agent_listener:
            self.agent_listener.unsubscribe(self._handle_event)
        if self.process_thread:
            self.process_thread.join(timeout=2)
        logger.info("MonitorService stopped")

    def set_socketio(self, socketio):
        self.socketio = socketio

    def _process_loop(self):
        """事件处理循环 - 从AgentListener消费事件"""
        while self.running:
            try:
                if not self.agent_listener:
                    time.sleep(1)
                    continue
                
                # 批量获取事件
                events = self.agent_listener.get_events(timeout=1.0)
                
                for event in events:
                    self._handle_event(event)
                    
            except Exception as e:
                logger.error(f"Process loop error: {e}")
                time.sleep(1)

    def _handle_event(self, ip: str, port: int, event: dict):
        """处理单个Agent事件（回调格式）"""
        event_type = event.get('type')
        source_ip = ip  # 使用传入的 ip
        path = event.get('path', '')
        timestamp = time.strftime('%H:%M:%S')
        
        # DEBUG: 记录所有收到的事件
        logger.info(f"[Monitor] Received event: type={event_type}, ip={source_ip}, path={path}")
        
        # 将 mask 转换为事件名称（兼容前端显示）
        mask = event.get('mask', 0)
        event_names = []
        if mask & 0x100:  # IN_CREATE
            event_names.append('CREATE')
        if mask & 0x2:    # IN_MODIFY
            event_names.append('MODIFY')
        if mask & 0x80:   # IN_MOVED_TO
            event_names.append('MOVED_TO')
        if mask & 0x40:   # IN_MOVED_FROM
            event_names.append('MOVED_FROM')
        if mask & 0x200:  # IN_DELETE
            event_names.append('DELETE')
        
        # 构建日志条目（兼容前端格式）
        log_entry = {
            'ip': source_ip,
            'time': timestamp,
            'type': event_type,
            'details': {
                'path': path,
                'mask': mask,
                'event': event_names[0] if event_names else 'FILE'
            }
        }
        
        # 存入内存日志
        self.logs.append(log_entry)
        if len(self.logs) > 1000:
            self.logs.pop(0)
        
        # 规则检测
        is_alert = False
        alert_msg = ""
        
        if event_type == 'file':
            is_alert, alert_msg = self._check_file_rules(path, event)
        elif event_type == 'process':
            is_alert, alert_msg = self._check_process_rules(event.get('cmd', ''))
        elif event_type == 'heartbeat':
            # 更新靶机监控状态
            self.tm.update_target_monitor_status(source_ip, 'online')
            return
        
        if is_alert:
            log_entry['alert'] = True
            log_entry['message'] = alert_msg
            
            with self.alert_lock:
                self.alert_count += 1
                self.last_alert_time = time.time()
            
            logger.warning(f"[{source_ip}] 🚨 ALERT: {alert_msg}")
            self._save_alert(log_entry)
            
            # WebSocket推送
            if hasattr(self, 'socketio') and self.socketio:
                try:
                    self.socketio.emit('monitor_alert', log_entry)
                except:
                    pass
        
        # 推送原始日志（用于实时视图）
        if hasattr(self, 'socketio') and self.socketio:
            try:
                self.socketio.emit('monitor_log', log_entry)
                logger.info(f"[Monitor] Pushed monitor_log via WebSocket: {log_entry}")
            except Exception as e:
                logger.error(f"[Monitor] WebSocket push failed: {e}")
        else:
            logger.warning(f"[Monitor] WebSocket not available, cannot push log")

    def _check_file_rules(self, path, event):
        """文件事件规则检测"""
        mask = event.get('mask', 0)
        
        # 规则1: Web脚本文件变更
        if any(path.endswith(ext) for ext in self.SUSPICIOUS_EXTS):
            # 新增文件特别关注
            if mask & 0x100:  # IN_CREATE
                return True, f"New script file created: {os.path.basename(path)}"
            elif mask & 0x2:  # IN_MODIFY
                return True, f"Script file modified: {os.path.basename(path)}"
        
        # 规则2: 隐藏文件
        filename = os.path.basename(path)
        if filename.startswith('.') and not filename.endswith('.swp'):
            return True, f"Hidden file activity: {filename}"
        
        # 规则3: 特殊目录
        if '/.git/' in path or '/.svn/' in path:
            return True, f"Version control file modified: {path}"
        
        return False, ""

    def _check_process_rules(self, cmd):
        """进程事件规则检测"""
        cmd_lower = cmd.lower()
        
        for pattern in self.DANGEROUS_CMDS:
            if pattern in cmd_lower:
                return True, f"Dangerous command detected: {cmd[:50]}..."
        
        return False, ""

    def _save_alert(self, alert_data):
        """持久化告警到文件"""
        alerts_file = os.path.join('data', 'monitor_alerts.json')
        
        with self.alert_lock:
            try:
                existing = []
                if os.path.exists(alerts_file):
                    try:
                        with open(alerts_file, 'r') as f:
                            existing = json.load(f)
                    except:
                        existing = []
                
                existing.append(alert_data)
                # 限制1000条
                if len(existing) > 1000:
                    existing = existing[-1000:]
                
                # 原子写入
                tmp_file = alerts_file + '.tmp'
                with open(tmp_file, 'w') as f:
                    json.dump(existing, f, indent=2)
                os.replace(tmp_file, alerts_file)
                
            except Exception as e:
                logger.error(f"Alert save error: {e}")

    def get_stats(self):
        """获取监控统计"""
        return {
            'total_logs': len(self.logs),
            'total_alerts': self.alert_count,
            'is_running': self.running,
            'using_agent_listener': self.agent_listener is not None
        }

    # ==================== 兼容旧接口（代理到AgentDeployer）====================

    def deploy_agent(self, ip, port, callback_ip=None, watch_dir="/var/www/html"):
        """
        部署Agent到靶机（代理方法，实际调用AgentDeployer）
        保持兼容性，供 DefenseManager 调用
        """
        logger.info(f"[{ip}:{port}] Deploying Agent via AgentDeployer...")
        
        if self.agent_deployer:
            success, msg = self.agent_deployer.deploy(ip, port, watch_dir)
            if success:
                logger.info(f"[{ip}:{port}] Agent deployed successfully via MonitorService")
            else:
                logger.error(f"[{ip}:{port}] Agent deployment failed: {msg}")
            return success, msg
        else:
            logger.error(f"[{ip}:{port}] AgentDeployer not available")
            return False, "AgentDeployer not available"

    def deploy_sh_agent(self, ip, port):
        """Shell Agent部署（已废弃，使用C Agent）"""
        logger.warning(f"[{ip}:{port}] Shell Agent is deprecated, use C Agent instead")
        return False, "Shell Agent deprecated"
