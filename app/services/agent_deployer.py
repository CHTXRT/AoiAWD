"""
Agent 部署管理器
负责编译、上传、启动、停止靶机探针
"""

import os
import logging
import threading
import time
import json
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger('AgentDeployer')


class AgentDeployer:
    """管理C探针的生命周期（编译、部署、控制）"""
    
    # 架构映射表
    ARCH_MAP = {
        'x86_64': 'wd_agent_x64',
        'amd64': 'wd_agent_x64',
        'aarch64': 'wd_agent_arm64',
        'arm64': 'wd_agent_arm64',
        'i686': 'wd_agent_x86',
        'i386': 'wd_agent_x86',
        'mips': 'wd_agent_mips',
        'mipsel': 'wd_agent_mipsel',
    }
    
    def __init__(self, connection_manager, target_manager, config=None):
        self.cm = connection_manager
        self.tm = target_manager
        self.config = config or {}
        
        # Agent状态: {(ip,port): {'status': 'running'|'stopped'|'error', 'pid': int, 'arch': str}}
        self.agent_status: Dict[tuple, dict] = {}
        self.status_lock = threading.RLock()
        
        # 探针目录
        self.agents_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'agents'
        )
        self.source_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'tools', 'agent', 'wd_agent.c'
        )
        
        # 回连端口
        self.callback_port = self.config.get('AGENT_CALLBACK_PORT', 8024)
        
        # 自动保存状态
        self.state_file = 'data/agent_status.json'
        self._load_state()
    
    def _load_state(self):
        """加载Agent状态"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        parts = k.split(':')
                        if len(parts) >= 2:
                            key = (parts[0], int(parts[1]))
                            self.agent_status[key] = v
            except Exception as e:
                logger.error(f"Failed to load agent state: {e}")
    
    def _save_state(self):
        """保存Agent状态"""
        try:
            data = {f"{k[0]}:{k[1]}": v for k, v in self.agent_status.items()}
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save agent state: {e}")
    
    def get_agent_path(self, arch: str) -> Optional[str]:
        """获取对应架构的Agent路径"""
        agent_name = self.ARCH_MAP.get(arch)
        if not agent_name:
            return None
        path = os.path.join(self.agents_dir, agent_name)
        return path if os.path.exists(path) else None
    
    def detect_arch(self, ip: str, port: int) -> Optional[str]:
        """检测靶机架构"""
        output = self.cm.execute(ip, port, "uname -m")
        arch = output.strip() if output else None
        logger.info(f"[{ip}:{port}] Detected arch: {arch}")
        return arch
    
    def check_agent_running(self, ip: str, port: int) -> bool:
        """检查Agent是否在运行（不触发自动连接）"""
        # 先检查连接状态，未连接直接返回 False，避免触发自动重连
        session_key = f"{ip}:{port}"
        if session_key not in self.cm.sessions:
            return False
        
        try:
            transport = self.cm.sessions[session_key].get_transport()
            if not transport or not transport.is_active():
                return False
        except:
            return False
        
        # 连接正常，再检查进程
        try:
            output = self.cm.execute(ip, port, "ps aux | grep wd_agent | grep -v grep")
            return output and 'wd_agent' in output
        except:
            return False
    
    def deploy(self, ip: str, port: int, watch_dir: str = "/var/www/html",
               force: bool = False) -> Tuple[bool, str]:
        """
        部署Agent到靶机
        
        Args:
            ip: 靶机IP
            port: SSH端口
            watch_dir: 监控目录
            force: 强制重新部署
        
        Returns:
            (success, message)
        """
        key = (ip, port)
        logger.info(f"[{ip}:{port}] Starting Agent deployment...")
        
        with self.status_lock:
            # 检查是否已运行
            if not force and self.check_agent_running(ip, port):
                logger.info(f"[{ip}:{port}] Agent already running")
                return True, "Agent already running"
            
            # 获取本地IP（用于回连）- 和AOI控件一致：1.靶机特定 2.全局设置 3.自动检测
            target = self.tm.get_target(ip, port)
            local_ip = None
            
            # Debug: 打印 target 中的 local_ip 值
            if target:
                logger.info(f"[{ip}:{port}] Target local_ip field: {target.get('local_ip')!r}, global: {self.tm.get_local_ip()!r}")
            
            # 1. 靶机特定的本地IP（最高优先级，和AOI一致）
            if target and target.get('local_ip'):
                local_ip = target['local_ip']
                logger.info(f"[{ip}:{port}] Using target-specific local IP: {local_ip}")
            
            # 2. 全局本机IP设置
            if not local_ip:
                global_ip = self.tm.get_local_ip()
                if global_ip:
                    # 直接使用用户设置的主机名（如 host.docker.internal）
                    # 不要转换为 IP，因为 Docker 环境下主机名能正常解析但 IP 可能被防火墙阻止
                    local_ip = global_ip
                    logger.info(f"[{ip}:{port}] Using global local IP/hostname: {local_ip}")
            
            # 2. 尝试从连接获取
            if not local_ip:
                local_ip = self.cm.get_local_ip_for_target(ip, port)
                if local_ip:
                    logger.info(f"[{ip}:{port}] Using local IP from connection: {local_ip}")
            
            # 3. 最后自动检测
            if not local_ip:
                local_ip = self._get_default_ip()
                logger.info(f"[{ip}:{port}] Auto-detected local IP: {local_ip}")
            
            if not local_ip:
                logger.error(f"[{ip}:{port}] Cannot determine local IP for callback")
                return False, "Cannot determine local IP for callback"
            
            # 检测架构
            logger.info(f"[{ip}:{port}] Detecting target architecture...")
            arch = self.detect_arch(ip, port)
            if not arch:
                logger.error(f"[{ip}:{port}] Cannot detect target architecture")
                return False, "Cannot detect target architecture"
            logger.info(f"[{ip}:{port}] Detected architecture: {arch}")
            
            # 查找Agent二进制
            agent_path = self.get_agent_path(arch)
            logger.info(f"[{ip}:{port}] Looking for agent: {self.ARCH_MAP.get(arch)} -> {agent_path}")
            
            if not agent_path:
                # 尝试编译
                if arch in self.ARCH_MAP:
                    logger.info(f"[{ip}:{port}] Agent not found, trying to build for {arch}...")
                    if self._build_agent(arch):
                        agent_path = self.get_agent_path(arch)
                
                if not agent_path:
                    # 回退到x64尝试
                    logger.warning(f"[{ip}:{port}] Arch {arch} not found, trying fallback to x64...")
                    agent_path = self.get_agent_path('x86_64')
                    if not agent_path:
                        logger.error(f"[{ip}:{port}] No agent binary available for arch: {arch} or x86_64")
                        return False, f"No agent binary for arch: {arch}"
                    logger.warning(f"[{ip}:{port}] Using x86_64 as fallback")
            
            logger.info(f"[{ip}:{port}] Using agent binary: {agent_path}")
            
            # 上传Agent
            remote_path = f"/tmp/.wd_{int(time.time()) % 10000}"
            logger.info(f"[{ip}:{port}] Uploading agent to {remote_path}...")
            success, msg = self.cm.upload(ip, port, agent_path, remote_path)
            if not success:
                logger.error(f"[{ip}:{port}] Upload failed: {msg}")
                return False, f"Upload failed: {msg}"
            logger.info(f"[{ip}:{port}] Upload successful")
            
            # 启动Agent（修复：直接使用 -d 守护模式，不用 nohup）
            log_file = f"/tmp/.wd_{int(time.time()) % 10000}.log"
            
            # 先杀掉旧进程
            self.cm.execute(ip, port, f"pkill -f '.wd_' 2>/dev/null; sleep 0.5")
            
            logger.info(f"[{ip}:{port}] Starting agent with callback to {local_ip}:{self.callback_port}...")
            logger.info(f"[{ip}:{port}] Agent log will be at: {log_file}")
            
            # 先测试网络连通性
            nc_test = self.cm.execute(ip, port, f"nc -zv {local_ip} {self.callback_port} 2>&1 || echo 'NC_FAILED'")
            if 'succeeded' in nc_test.lower() or 'open' in nc_test.lower():
                logger.info(f"[{ip}:{port}] Network test OK: can connect to {local_ip}:{self.callback_port}")
            else:
                logger.warning(f"[{ip}:{port}] Network test FAILED: {nc_test}")
            
            # 测试 Agent 是否能解析主机名
            dns_test = self.cm.execute(ip, port, f"getent hosts {local_ip} 2>&1 || nslookup {local_ip} 2>&1 || echo 'DNS_LOOKUP_FAILED'")
            logger.info(f"[{ip}:{port}] DNS lookup test for {local_ip}: {dns_test[:200]}")
            
            # 启动 Agent（不使用 -d，而用 nohup + & 后台运行，这样可以捕获日志）
            start_cmd = f"chmod +x {remote_path} && nohup {remote_path} {local_ip} {self.callback_port} {watch_dir} -v"
            logger.info(f"[{ip}:{port}] Agent start command: {start_cmd}")
            
            # 在后台启动，重定向输出到日志文件
            self.cm.execute(ip, port, f"{start_cmd} >{log_file} 2>&1 </dev/null &")
            
            # 等待 Agent 启动
            time.sleep(2)
            
            # 获取Agent启动日志
            agent_log = self.cm.execute(ip, port, f"cat {log_file} 2>/dev/null || echo 'NO_LOG_FILE'")
            if agent_log and 'NO_LOG_FILE' not in agent_log:
                logger.info(f"[{ip}:{port}] Agent startup log ({len(agent_log)} chars):\n{agent_log[:2000]}")
            else:
                logger.warning(f"[{ip}:{port}] Agent log file empty or not found")
            
            # 检查进程是否真的在运行
            pid_check = self.cm.execute(ip, port, f"ps aux | grep -v grep | grep '{remote_path}' || echo 'NOT_RUNNING'")
            logger.info(f"[{ip}:{port}] Agent process check: {pid_check[:200]}")
            
            if remote_path in pid_check:
                # 启动成功
                self.agent_status[key] = {
                    'status': 'running',
                    'arch': arch,
                    'remote_path': remote_path,
                    'watch_dir': watch_dir,
                    'local_ip': local_ip,
                    'started_at': time.time()
                }
                self._save_state()
                logger.info(f"[{ip}:{port}] Agent deployed and running successfully")
                return True, "Agent deployed and running"
            else:
                # 启动失败，清理
                logger.error(f"[{ip}:{port}] Agent failed to start. Output: {output}")
                self.cm.execute(ip, port, f"rm -f {remote_path}")
                return False, f"Agent failed to start: {output}"
    
    def stop(self, ip: str, port: int) -> Tuple[bool, str]:
        """停止靶机上的Agent"""
        key = (ip, port)
        
        # 查找并kill进程
        output = self.cm.execute(ip, port, 
            "ps aux | grep wd_agent | grep -v grep | awk '{print $2}'")
        
        killed = False
        if output:
            pids = [p.strip() for p in output.split('\n') if p.strip().isdigit()]
            for pid in pids:
                self.cm.execute(ip, port, f"kill -9 {pid}")
                killed = True
        
        # 清理文件
        info = self.agent_status.get(key, {})
        remote_path = info.get('remote_path')
        if remote_path:
            self.cm.execute(ip, port, f"rm -f {remote_path}")
        
        # 清理所有可能的Agent文件
        self.cm.execute(ip, port, "rm -f /tmp/.wd_*")
        
        with self.status_lock:
            if key in self.agent_status:
                self.agent_status[key]['status'] = 'stopped'
                self._save_state()
        
        msg = "Agent stopped" if killed else "Agent not running"
        logger.info(f"[{ip}:{port}] {msg}")
        return True, msg
    
    def get_status(self, ip: str, port: int) -> dict:
        """获取Agent状态"""
        key = (ip, port)
        status = self.agent_status.get(key, {}).copy()
        status['is_running'] = self.check_agent_running(ip, port)
        return status
    
    def get_all_status(self) -> Dict[tuple, dict]:
        """获取所有靶机的Agent状态"""
        result = {}
        for target in self.tm.targets:
            key = (target['ip'], target['port'])
            result[key] = self.get_status(target['ip'], target['port'])
        return result
    
    def batch_deploy(self, watch_dir: str = "/var/www/html") -> List[dict]:
        """批量部署到所有已连接靶机"""
        results = []
        threads = []
        results_lock = threading.Lock()
        
        def deploy_one(target):
            ip, port = target['ip'], target['port']
            if target.get('status') != 'connected':
                return
            
            success, msg = self.deploy(ip, port, watch_dir)
            with results_lock:
                results.append({
                    'ip': ip,
                    'port': port,
                    'success': success,
                    'message': msg
                })
        
        for target in self.tm.targets:
            t = threading.Thread(target=deploy_one, args=(target,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=30)
        
        return results
    
    def batch_stop(self) -> List[dict]:
        """批量停止所有靶机的Agent"""
        results = []
        threads = []
        results_lock = threading.Lock()
        
        def stop_one(target):
            ip, port = target['ip'], target['port']
            success, msg = self.stop(ip, port)
            with results_lock:
                results.append({
                    'ip': ip,
                    'port': port,
                    'success': success,
                    'message': msg
                })
        
        for target in self.tm.targets:
            t = threading.Thread(target=stop_one, args=(target,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=10)
        
        return results
    
    def _build_agent(self, arch: str) -> bool:
        """尝试编译Agent"""
        import subprocess
        
        makefile_dir = os.path.dirname(self.source_file)
        target = self.ARCH_MAP.get(arch, 'x64')
        
        try:
            result = subprocess.run(
                ['make', target],
                cwd=makefile_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0 and os.path.exists(
                os.path.join(self.agents_dir, self.ARCH_MAP.get(arch, ''))
            )
        except Exception as e:
            logger.error(f"Build failed: {e}")
            return False
    
    def _get_default_ip(self) -> Optional[str]:
        """获取默认本地IP"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def health_check(self, ip: str, port: int) -> Tuple[bool, str]:
        """健康检查：Agent是否正常工作"""
        running = self.check_agent_running(ip, port)
        
        key = (ip, port)
        with self.status_lock:
            if key in self.agent_status:
                self.agent_status[key]['last_check'] = time.time()
                self.agent_status[key]['is_running'] = running
        
        if running:
            return True, "Agent is running"
        
        # 如果记录显示运行但实际不在，更新状态
        if key in self.agent_status and self.agent_status[key].get('status') == 'running':
            self.agent_status[key]['status'] = 'stopped'
            self._save_state()
        
        return False, "Agent not running"
