import logging
import threading
import time
import os
import shlex
import json
import hashlib
import tempfile
import tarfile
from typing import Optional, Callable

logger = logging.getLogger('Immortal')
logger.setLevel(logging.INFO)


class ImmortalShellKiller:
    """
    不死马查杀器 - 支持双模式：
    1. Agent模式（推荐）: 事件驱动，实时响应，低SSH开销
    2. SSH轮询模式（Fallback）: 定时扫描，高兼容
    """
    
    # 工作模式
    MODE_AGENT = 'agent'      # Agent事件驱动
    MODE_SSH = 'ssh'          # SSH轮询
    MODE_HYBRID = 'hybrid'    # 混合（Agent优先，失败转SSH）
    
    def __init__(self, connection_manager, target_manager, socketio=None, 
                 agent_deployer=None, agent_listener=None):
        logger.info(f"Initialized. ID={id(self)}")
        self.cm = connection_manager
        self.tm = target_manager
        self.socketio = socketio
        
        # Agent组件（可选，如未提供则回退到纯SSH模式）
        self.agent_deployer = agent_deployer
        self.agent_listener = agent_listener
        
        # 监听器引用（用于事件循环）
        self._event_processor_thread: Optional[threading.Thread] = None
        self._event_processor_running = False
        
        # 模式配置
        self.default_mode = self.MODE_HYBRID
        self.target_modes = {}  # {(ip,port): mode}
        
        # 原有监控线程管理
        self.monitors = {}  # "ip:port" -> threading.Event (stop_event)
        self.lock = threading.Lock()
        
        # 加载告警
        import app.config
        self.log_file = app.config.Config.IMMORTAL_LOG_FILE
        self.alerts = self._load_alerts()
        
        # Persistent Killers State
        self.killers_file = 'data/active_killers.json'
        self.active_killers = {}
        self._load_active_killers()
        
        # Concurrency Control
        self.processing_files = set()
        self.processing_lock = threading.Lock()

    def set_socketio(self, socketio):
        self.socketio = socketio
        logger.info(f"SocketIO set to {socketio}")
    
    def set_agent_components(self, deployer, listener):
        """设置Agent组件（通常在初始化后调用）"""
        self.agent_deployer = deployer
        self.agent_listener = listener
        logger.info("Agent components connected")
    
    # ==================== 模式控制 ====================
    
    def set_mode(self, ip: str, port: int, mode: str):
        """
        设置查杀模式
        
        Args:
            mode: 'agent' | 'ssh' | 'hybrid'
        """
        if mode not in (self.MODE_AGENT, self.MODE_SSH, self.MODE_HYBRID):
            raise ValueError(f"Invalid mode: {mode}")
        
        key = (ip, port)
        self.target_modes[key] = mode
        logger.info(f"[{ip}:{port}] Mode set to {mode}")
    
    def get_mode(self, ip: str, port: int) -> str:
        """获取当前模式"""
        key = (ip, port)
        return self.target_modes.get(key, self.default_mode)
    
    def _should_use_agent(self, ip: str, port: int) -> bool:
        """判断是否应该使用Agent模式"""
        mode = self.get_mode(ip, port)
        
        if mode == self.MODE_SSH:
            return False
        
        if mode == self.MODE_AGENT or mode == self.MODE_HYBRID:
            if self.agent_deployer and self.agent_listener:
                # 检查Agent是否运行
                status = self.agent_deployer.get_status(ip, port)
                return status.get('is_running', False)
        
        return False
    
    # ==================== 启动/停止监控 ====================
    
    def start_monitoring(self, ip, port, mode: Optional[str] = None):
        """启动监控"""
        key = f"{ip}:{port}"
        
        if mode:
            self.set_mode(ip, port, mode)
        
        with self.lock:
            if key in self.monitors:
                logger.info(f"[{key}] Immortal Killer already running")
                return
            
            # 强制模式：如果显式指定了agent模式，跳过运行时检查
            current_mode = self.get_mode(ip, port)
            if mode == self.MODE_AGENT:
                logger.info(f"[{key}] Forcing Agent mode (explicitly set)")
            
            stop_event = threading.Event()
            self.monitors[key] = stop_event
            
            # 根据模式选择监控方式
            current_mode = self.get_mode(ip, port)
            
            # 如果显式指定了agent模式，强制使用Agent（跳过运行时检查）
            if mode == self.MODE_AGENT or current_mode == self.MODE_AGENT:
                use_agent = True
                logger.info(f"[{key}] Using AGENT mode (explicitly configured)")
            else:
                use_agent = self._should_use_agent(ip, port)
            
            if use_agent:
                # Agent模式：不创建轮询线程，依赖事件处理器
                logger.info(f"[{key}] Starting AGENT event-driven monitoring")
                # 确保事件处理器在运行
                self._ensure_event_processor()
            else:
                # SSH轮询模式
                logger.info(f"[{key}] Starting SSH poll mode monitoring")
                t = threading.Thread(
                    target=self._monitoring_loop_ssh, 
                    args=(ip, port, stop_event), 
                    daemon=True
                )
                t.start()
            
            logger.info(f"[{key}] Started (ID={id(self)}, mode={current_mode})")

    def stop_monitoring(self, ip, port):
        """停止监控"""
        key = f"{ip}:{port}"
        with self.lock:
            if key in self.monitors:
                self.monitors[key].set()
                del self.monitors[key]
                logger.info(f"[{key}] Stopped")

    def is_monitoring(self, ip, port):
        """检查是否在监控"""
        key = f"{ip}:{port}"
        with self.lock:
            return key in self.monitors
    
    def get_monitoring_targets(self):
        """获取所有监控中的目标"""
        with self.lock:
            return list(self.monitors.keys())

    # ==================== SSH轮询模式 ====================
    
    def _monitoring_loop_ssh(self, ip, port, stop_event):
        """SSH轮询监控循环（原有逻辑）"""
        while not stop_event.is_set():
            try:
                self._scan_and_kill_ssh(ip, port)
            except Exception as e:
                logger.error(f"[{ip}:{port}] SSH poll error: {e}")
            
            # 10秒间隔
            if stop_event.wait(10):
                break

    def _scan_and_kill_ssh(self, ip, port):
        """SSH扫描（原有逻辑，优化版）"""
        # Check Maintenance Mode
        target = self.tm.get_target(ip, port)
        if target and target.get('maintenance_mode'):
            return

        # 检查是否应该切换到Agent模式
        if self._should_use_agent(ip, port):
            logger.info(f"[{ip}:{port}] Agent detected, switching to event-driven mode")
            return

        # 正则模式 - 只扫描5分钟内修改的文件
        regex_pattern = r"eval\(|assert\(|system\(|shell_exec\(|passthru\(|pcntl_exec\(|popen\(|proc_open\(|ignore_user_abort|set_time_limit"
        
        cmd_find_grep = f"find /var/www/html -type f -name '*.php' -not -path '*/.quarantine/*' -mmin -5 -print0 2>/dev/null | xargs -0 grep -lE '{regex_pattern}'"
        
        files_out = self.cm.execute(ip, port, cmd_find_grep)
        
        if not files_out: 
            return

        files = [f.strip() for f in files_out.split('\n') if f.strip().endswith('.php')]
        
        for file_path in files:
            # 排除AOI工具
            filename = os.path.basename(file_path)
            if filename.startswith('TapeWorm') or filename.startswith('.tapeworm'):
                continue
            
            # 白名单检查
            if target and 'whitelist' in target and file_path in target['whitelist']:
                continue

            # 强制删除列表
            if target and 'force_delete_files' in target and file_path in target['force_delete_files']:
                logger.warning(f"[{ip}:{port}] Force Deleting: {file_path}")
                self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir -p {file_path}")
                continue

            # 线程化处理
            key = f"{ip}:{port}:{file_path}"
            with self.processing_lock:
                if key in self.processing_files:
                    continue
                self.processing_files.add(key)
            
            threading.Thread(
                target=self._remediate_wrapper, 
                args=(ip, port, file_path), 
                daemon=True
            ).start()

    # ==================== Agent事件驱动模式 ====================
    
    def _ensure_event_processor(self):
        """确保事件处理器在运行（订阅模式）"""
        if self._event_processor_running:
            return
        
        if not self.agent_listener:
            logger.warning("Agent listener not available")
            return
        
        self._event_processor_running = True
        # 注册回调，而不是启动拉取线程
        self.agent_listener.subscribe(self._handle_agent_event)
        logger.info("Immortal killer subscribed to agent events")
    
    def _event_processor_loop(self):
        """事件处理主循环"""
        while self._event_processor_running:
            try:
                if not self.agent_listener:
                    time.sleep(1)
                    continue
                
                # 获取事件（1秒超时）
                events = self.agent_listener.get_events(timeout=1.0)
                
                for event in events:
                    self._handle_agent_event(event)
                    
            except Exception as e:
                logger.error(f"Event processor error: {e}")
                time.sleep(1)
    
    def _handle_agent_event(self, ip: str, port: int, event: dict):
        """处理Agent上报的文件事件（回调格式）"""
        source_ip = ip
        file_path = event.get('path', '')
        
        if not source_ip or not file_path:
            return
        
        # 1. 找出所有匹配该 Source IP 的 Target
        matching_targets = []
        
        # 遍历所有 registered targets
        for t in self.tm.targets:
            if t['ip'] == source_ip:
                matching_targets.append(t)
        
        if not matching_targets:
            logger.debug(f"No targets found for Agent IP {source_ip}")
            return

        # 2. 遍历所有匹配的 Target，分别检查监控状态
        for target in matching_targets:
            target_port = target['port']
            key = f"{source_ip}:{target_port}"
            
            # 检查该target是否处于监控状态
            is_monitored = False
            with self.lock:
                if key in self.monitors:
                    is_monitored = True
            
            if not is_monitored:
                continue

            # 检查维护模式
            if target.get('maintenance_mode'):
                continue
            
            # 检查是否在处理中 (针对每个 {ip}:{port}:{file} 唯一)
            proc_key = f"{source_ip}:{target_port}:{file_path}"
            with self.processing_lock:
                if proc_key in self.processing_files:
                    continue
                self.processing_files.add(proc_key)
            
            # 异步处理
            threading.Thread(
                target=self._remediate_wrapper,
                args=(source_ip, target_port, file_path),
                daemon=True
            ).start()
            
            logger.info(f"[Agent] Processing event for {source_ip}:{target_port} - {file_path}")

    def stop_event_processor(self):
        """停止事件处理器"""
        self._event_processor_running = False
        if self._event_processor_thread:
            self._event_processor_thread.join(timeout=3)

    # ==================== 查杀处理 ====================
    
    def _remediate_wrapper(self, ip, port, file_path):
        """包装器，确保处理状态清理"""
        try:
            self._remediate(ip, port, file_path)
        except Exception as e:
            logger.error(f"[{ip}:{port}] Remediation Error ({file_path}): {e}")
        finally:
            key = f"{ip}:{port}:{file_path}"
            with self.processing_lock:
                self.processing_files.discard(key)

    def _remediate(self, ip, port, file_path):
        """
        执行查杀（支持Agent和SSH两种来源的事件）
        原有逻辑，保持不变
        """
        # 0. 基础过滤（文件名/白名单）
        target = self.tm.get_target(ip, port)
        if not target:
            return

        filename = os.path.basename(file_path)
        
        # 0.1 AOI工具文件名过滤
        if filename.startswith('TapeWorm') or filename.startswith('.tapeworm'):
            return
            
        # 0.2 白名单检查
        if 'whitelist' in target and file_path in target['whitelist']:
            logger.info(f"[{ip}:{port}] Ignored whitelisted file: {file_path}")
            return

        # 0.3 强制删除列表
        if 'force_delete_files' in target and file_path in target['force_delete_files']:
            logger.warning(f"[{ip}:{port}] Force Deleting: {file_path}")
            self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir -p {file_path}")
            return

        # 0.4 安全检查：与备份或快照匹配则跳过
        if self._is_safe_baseline(ip, port, file_path):
            return

        # 0.5. 检查AOI/WAF修改
        if self._is_aoi_modified(ip, port, file_path):
            try:
                md5_out = self.cm.execute(ip, port, f"md5sum {file_path}")
                if md5_out and ' ' in md5_out:
                    md5_val = md5_out.split()[0].strip()
                    threading.Thread(
                        target=self.tm.update_single_snapshot, 
                        args=(ip, port, file_path, md5_val), 
                        daemon=True
                    ).start()
            except: 
                pass
            return

        logger.warning(f"[{ip}:{port}] IMMORTAL SHELL DETECTED: {file_path}")
        
        remediation_log = []
        quarantine_path = None
        
        # 1. 杀进程
        pids = self.cm.execute(ip, port, f"lsof -t {file_path}")
        if not pids: 
            pids = self.cm.execute(ip, port, f"fuser {file_path} 2>/dev/null")
        
        if pids:
            for pid in pids.split():
                if pid.strip().isdigit():
                    self.cm.execute(ip, port, f"kill -9 {pid.strip()}")
                    remediation_log.append(f"Killed PID {pid.strip()}")

        # 2. 隔离
        try:
            timestamp = int(time.time())
            filename = os.path.basename(file_path)
            quarantine_dir = "/tmp/.quarantine"
            quarantine_file = f"{quarantine_dir}/{filename}_{timestamp}"
            
            self.cm.execute(ip, port, f"mkdir -p {quarantine_dir}")
            self.cm.execute(ip, port, f"cp {file_path} {quarantine_file}")
            quarantine_path = quarantine_file
            remediation_log.append("Quarantined")
        except: 
            pass

        # 3. 从备份恢复
        target = self.tm.get_target(ip, port)
        backup_path = target.get('backup_path') if target else None
        
        restored = False
        if backup_path and os.path.exists(backup_path) and backup_path.endswith('.tar'):
            try:
                rel_path_in_tar = file_path.lstrip('/')
                
                with tarfile.open(backup_path, 'r') as tar:
                    try:
                        member = tar.getmember(rel_path_in_tar)
                        f_obj = tar.extractfile(member)
                        if f_obj:
                            tmp_restore = os.path.join(
                                tempfile.gettempdir(), 
                                f"restore_{filename}_{timestamp}"
                            )
                            with open(tmp_restore, 'wb') as f_dst:
                                f_dst.write(f_obj.read())
                            
                            self.cm.upload(ip, port, tmp_restore, file_path)
                            os.remove(tmp_restore)
                            
                            restored = True
                            remediation_log.append("Restored from Local Backup")
                            logger.info(f"[{ip}:{port}] Restored {file_path} from backup")
                    except KeyError:
                        pass
            except Exception as e:
                logger.error(f"[{ip}:{port}] Restore Error: {e}")

        # 4. 未恢复则删除+占位
        if not restored:
            self.cm.execute(ip, port, f"rm -rf {file_path} && mkdir -p {file_path}")
            remediation_log.append("Deleted & Placeheld")

        # 5. 锁定
        self.cm.execute(ip, port, f"chattr +i {file_path} 2>/dev/null")
        remediation_log.append("Locked")

        # 6. 告警
        self._send_alert(ip, port, file_path, ", ".join(remediation_log), quarantine_path)

    # ==================== 辅助方法（保持原有逻辑） ====================

    def _is_safe_baseline(self, ip, port, file_path):
        """检查文件是否与备份或快照匹配"""
        target = self.tm.get_target(ip, port)
        if not target: 
            return False

        # 1. 检查快照
        snapshot = target.get('file_snapshot', {})
        if snapshot and file_path in snapshot:
            try:
                remote_md5_out = self.cm.execute(ip, port, f"md5sum {file_path}")
                if remote_md5_out and ' ' in remote_md5_out:
                    remote_md5 = remote_md5_out.split()[0].strip()
                    if remote_md5 == snapshot[file_path]:
                        return True
            except: 
                pass

        # 2. 检查备份
        backup_path = target.get('backup_path')
        if backup_path and os.path.exists(backup_path):
            try:
                remote_md5_out = self.cm.execute(ip, port, f"md5sum {file_path}")
                if not remote_md5_out or ' ' not in remote_md5_out: 
                    return False
                remote_md5 = remote_md5_out.split()[0].strip()
                
                rel_path = file_path.lstrip('/')
                with tarfile.open(backup_path, 'r') as tar:
                    try:
                        member = tar.getmember(rel_path)
                        f_obj = tar.extractfile(member)
                        if f_obj:
                            backup_md5 = hashlib.md5(f_obj.read()).hexdigest()
                            if remote_md5 == backup_md5:
                                return True
                    except KeyError:
                        pass
            except: 
                pass
        
        return False

    def _is_aoi_modified(self, ip, port, file_path):
        """检查是否为AOI工具修改"""
        try:
            content_out = self.cm.execute(ip, port, f"head -n 50 {file_path}")
            if not content_out: 
                return False
            
            signatures = [
                'TAPEWORMINSTALLED',
                'TapeWorm', 
                '.tapeworm', 
                'roundworm', 
                'waf.php', 
                'AWD-Defender AOI',
            ]
            
            content_lower = content_out.lower()
            
            for sig in signatures:
                if sig.lower() in content_lower:
                    return True
            
            if 'include' in content_lower and 'tapeworm' in content_lower and '.php' in content_lower:
                return True

            return False
        except Exception as e:
            return False

    def _send_alert(self, ip, port, file_path, action, quarantine_path=None):
        """发送告警"""
        target = self.tm.get_target(ip, port)
        target_name = target.get('name', '') if target else ''
        
        timestamp = time.strftime('%H:%M:%S')
        
        data = {
            'ip': ip,
            'port': port,
            'target_name': target_name,
            'file': file_path,
            'time': timestamp,
            'action': action,
            'quarantine_path': quarantine_path,
            'type': 'immortal_shell',
            'source': 'agent' if self._should_use_agent(ip, port) else 'ssh'
        }
        
        with self.lock:
            self.alerts.append(data)
            self._save_alerts()
        
        if self.socketio: 
            try:
                self.socketio.emit('immortal_alert', data)
            except Exception as e:
                logger.error(f"[{ip}:{port}] SocketIO Emit Error: {e}")

    # ==================== 数据持久化（保持原有） ====================

    def _load_alerts(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            except: 
                pass
        return []

    def _save_alerts(self):
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.alerts, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving alerts: {e}")

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def clear_alerts(self):
        with self.lock:
            self.alerts = []
            self._save_alerts()
            logger.info("Alerts cleared")

    def _load_active_killers(self):
        if os.path.exists(self.killers_file):
            try:
                with open(self.killers_file, 'r', encoding='utf-8') as f:
                    self.active_killers = json.load(f)
            except: 
                self.active_killers = {}
    
    def _save_active_killers(self):
        try:
            with open(self.killers_file, 'w', encoding='utf-8') as f:
                json.dump(self.active_killers, f, ensure_ascii=False, indent=2)
        except: 
            pass

    # ==================== 持久化查杀（保持原有） ====================

    def start_persistent_kill(self, ip, port, file_path):
        """启动持久化查杀脚本"""
        key = f"{ip}:{port}:{file_path}"
        if key in self.active_killers:
            return True, "Already running"

        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
        script_name = f".wd_kill_{file_hash}.sh"
        remote_script_path = f"/tmp/{script_name}"
        
        script_content = f"""#!/bin/bash
# WD-Defender Persistent Killer for {file_path}
TARGET="{file_path}"
while true; do
    if [ -f "$TARGET" ]; then
        rm -rf "$TARGET"
        fuser -k -9 "$TARGET" >/dev/null 2>&1
    fi
    if [ ! -d "$TARGET" ]; then
        mkdir -p "$TARGET"
        chmod 000 "$TARGET"
    fi
    sleep 0.1
done
"""
        try:
            local_tmp = os.path.join(tempfile.gettempdir(), script_name)
            with open(local_tmp, 'w', encoding='utf-8', newline='\n') as f:
                f.write(script_content)
            
            self.cm.upload(ip, port, local_tmp, remote_script_path)
            os.remove(local_tmp)
            
            self.cm.execute(ip, port, f"chmod +x {remote_script_path}")
            cmd = f"nohup {remote_script_path} >/dev/null 2>&1 &"
            self.cm.execute(ip, port, cmd)
            
            self.active_killers[key] = remote_script_path
            self._save_active_killers()
            
            return True, "Persistent killer started"
            
        except Exception as e:
            return False, str(e)

    def stop_persistent_kill(self, ip, port, file_path):
        """停止持久化查杀"""
        key = f"{ip}:{port}:{file_path}"
        if key not in self.active_killers:
            return False, "Not running"
            
        script_path = self.active_killers[key]
        script_name = os.path.basename(script_path)
        
        try:
            self.cm.execute(ip, port, f"pkill -f {script_name}")
            self.cm.execute(ip, port, f"rm -rf {script_path}")
            
            del self.active_killers[key]
            self._save_active_killers()
            
            return True, "Persistent killer stopped"
        except Exception as e:
            return False, str(e)

    def get_persistent_status(self, ip, port, file_path):
        key = f"{ip}:{port}:{file_path}"
        return key in self.active_killers

    def get_active_killers(self):
        result = []
        for key, script_path in self.active_killers.items():
            parts = key.split(':')
            if len(parts) >= 3:
                ip = parts[0]
                port = parts[1]
                file_path = ':'.join(parts[2:])
                
                result.append({
                    'ip': ip,
                    'port': port,
                    'file': file_path,
                    'script': script_path,
                    'status': 'Running'
                })
        return result

    def restore_from_quarantine(self, ip, port, file_path, quarantine_path):
        """从隔离区恢复"""
        logger.info(f"[{ip}:{port}] Restoring {file_path} from {quarantine_path}...")
        try:
            self.cm.execute(ip, port, f"chattr -i {file_path} 2>/dev/null")
            
            check = self.cm.execute(ip, port, f"test -f {quarantine_path} && echo EXISTS")
            if not check or "EXISTS" not in check:
                return False, "Quarantine file not found"
            
            self.cm.execute(ip, port, f"rm -rf {file_path}")
            self.cm.execute(ip, port, f"cp {quarantine_path} {file_path}")
            
            self.tm.add_whitelist(ip, port, file_path)
            
            return True, "Restored and Whitelisted"
        except Exception as e:
            logger.error(f"Restore error: {e}")
            return False, str(e)
    
    # ==================== 状态统计 ====================
    
    def get_stats(self) -> dict:
        """获取统计信息"""
        agent_targets = 0
        ssh_targets = 0
        
        for key in self.monitors.keys():
            parts = key.split(':')
            if len(parts) >= 2:
                ip, port = parts[0], int(parts[1])
                if self._should_use_agent(ip, port):
                    agent_targets += 1
                else:
                    ssh_targets += 1
        
        return {
            'total_monitoring': len(self.monitors),
            'agent_mode_targets': agent_targets,
            'ssh_mode_targets': ssh_targets,
            'processing_files': len(self.processing_files),
            'total_alerts': len(self.alerts),
            'active_killers': len(self.active_killers)
        }
