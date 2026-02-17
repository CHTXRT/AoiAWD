from flask import request, jsonify, current_app
import os
import threading
from werkzeug.utils import secure_filename
from app.services import ssh_manager
from . import bp

@bp.route('/api/rerun_preload', methods=['POST'])
def rerun_preload():
    data = request.json
    threading.Thread(target=ssh_manager.run_preload_tasks, args=(data['ip'], data['port'], True)).start()
    return jsonify({'status': 'ok', 'message': 'Preload tasks queued'})

@bp.route('/api/rerun_backup', methods=['POST'])
def rerun_backup():
    data = request.json
    threading.Thread(target=ssh_manager.backup_target, args=(data['ip'], data['port'], None, True)).start()
    return jsonify({'status': 'ok', 'message': 'Backup tasks queued'})

@bp.route('/api/preload/add_file', methods=['POST'])
def add_preload_file():
    file = request.files['file']
    remote_path = request.form['remote_path']
    
    filename = secure_filename(file.filename)
    local_path = os.path.join(current_app.config['PRELOAD_FOLDER'], filename)
    file.save(local_path)
    
    ssh_manager.preload_config['files'].append({
        'filename': filename,
        'remote_path': remote_path
    })
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/preload/add_cmd', methods=['POST'])
def add_preload_cmd():
    cmd = request.json['cmd']
    ssh_manager.preload_config['commands'].append(cmd)
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/preload/remove', methods=['POST'])
def remove_preload():
    data = request.json
    idx = data['index']
    
    if data['type'] == 'file':
        ssh_manager.preload_config['files'].pop(int(idx))
    elif data['type'] == 'cmd':
        ssh_manager.preload_config['commands'].pop(int(idx))
    
    ssh_manager.save_preload_config()
    return jsonify({'status': 'ok'})

@bp.route('/api/snapshot', methods=['POST'])
def api_snapshot():
    """建立文件快照基线"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    threading.Thread(target=ssh_manager.snapshot_files, args=(ip, port)).start()
    return jsonify({'status': 'ok', 'message': '快照任务已启动'})

@bp.route('/api/scan_backdoor', methods=['POST'])
def api_scan_backdoor():
    """扫描后门/不死马"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    threading.Thread(target=ssh_manager.scan_backdoor, args=(ip, port)).start()
    return jsonify({'status': 'ok', 'message': '后门扫描已启动'})

@bp.route('/api/backdoor_results', methods=['POST'])
def api_backdoor_results():
    """获取后门扫描结果"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    target = next((t for t in ssh_manager.targets if t['ip'] == ip and t['port'] == int(port)), None)
    if not target:
        return jsonify({'error': '靶机未找到'}), 404
    return jsonify({
        'backdoor_scan': target.get('backdoor_scan'),
        'snapshot_time': target.get('snapshot_time'),
        'snapshot_count': len(target.get('file_snapshot', {})),
    })

@bp.route('/api/restore_backup', methods=['POST'])
def api_restore_backup():
    """还原备份"""
    data = request.json
    ip, port = data['ip'], data.get('port', 22)
    success, msg = ssh_manager.restore_backup(ip, port)
    return jsonify({'success': success, 'message': msg})

@bp.route('/api/scheduled_tasks', methods=['GET'])
def api_get_scheduled_tasks():
    """获取定时任务列表"""
    return jsonify({'tasks': ssh_manager.get_scheduled_tasks()})

@bp.route('/api/scheduled_task/add', methods=['POST'])
def api_add_scheduled_task():
    """添加定时任务"""
    data = request.json
    name = data.get('name', '')
    cmd = data.get('cmd', '')
    interval = data.get('interval', 60)
    if not name or not cmd:
        return jsonify({'error': '名称和命令不能为空'}), 400
    ssh_manager.add_scheduled_task(name, cmd, interval)
    return jsonify({'status': 'ok', 'message': f'定时任务 {name} 已添加'})

@bp.route('/api/scheduled_task/remove', methods=['POST'])
def api_remove_scheduled_task():
    """移除定时任务"""
    data = request.json
    name = data.get('name', '')
    if ssh_manager.remove_scheduled_task(name):
        return jsonify({'status': 'ok', 'message': f'定时任务 {name} 已移除'})
    return jsonify({'error': '任务未找到'}), 404

@bp.route('/api/local_ip', methods=['GET'])
def api_get_local_ip():
    """获取本机 IP"""
    return jsonify({'local_ip': ssh_manager.get_local_ip()})

@bp.route('/api/local_ip', methods=['POST'])
def api_set_local_ip():
    """设置本机 IP"""
    data = request.json
    ip = data.get('ip', '')
    ssh_manager.set_local_ip(ip)
    return jsonify({'status': 'ok', 'local_ip': ip})

@bp.route('/api/deploy_aoi', methods=['POST'])
def api_deploy_aoi():
    """手动部署 AOI 工具到指定靶机"""
    data = request.json
    ip = data['ip']
    port = int(data.get('port', 22))
    def _run():
        ssh_manager.deploy_aoi_tools(ip, port)
    threading.Thread(target=_run).start()
    return jsonify({'status': 'ok', 'message': 'AOI 部署已启动'})

@bp.route('/api/defense/immortal/alerts', methods=['GET'])
def api_get_immortal_alerts():
    """获取不死马查杀历史告警"""
    return jsonify({'alerts': ssh_manager.get_immortal_alerts()})

@bp.route('/api/defense/immortal/alerts/clear', methods=['POST'])
def api_clear_immortal_alerts():
    """清空不死马查杀历史告警"""
    ssh_manager.clear_immortal_alerts()
    return jsonify({'status': 'ok', 'message': '告警记录已清空'})

@bp.route('/api/defense/whitelist/add', methods=['POST'])
def api_add_whitelist():
    data = request.json
    ssh_manager.add_whitelist(data['ip'], int(data.get('port', 22)), data['file'])
    return jsonify({'status': 'ok', 'message': '已加入白名单'})

@bp.route('/api/defense/whitelist/remove', methods=['POST'])
def api_remove_whitelist():
    data = request.json
    ssh_manager.remove_whitelist(data['ip'], int(data.get('port', 22)), data['file'])
    return jsonify({'status': 'ok', 'message': '已移出白名单'})

@bp.route('/api/defense/quarantine/restore', methods=['POST'])
def api_restore_quarantine():
    data = request.json
    success, msg = ssh_manager.restore_quarantine(data['ip'], int(data.get('port', 22)), data['file'], data['quarantine_path'])
    return jsonify({'status': 'ok' if success else 'error', 'message': msg})

@bp.route('/api/target/maintenance', methods=['POST'])
def api_maintenance_mode():
    data = request.json
    res = ssh_manager.tm.toggle_maintenance_mode(data['ip'], int(data.get('port', 22)), data['enabled'])
    return jsonify({'status': 'ok' if res else 'error'})

@bp.route('/api/defense/immortal/kill_persist', methods=['POST'])
def api_kill_persist():
    data = request.json
    ip = data['ip']
    port = data.get('port', 22)
    file_path = data['file']
    action = data.get('action', 'start') # start | stop
    
    if action == 'start':
        success, msg = ssh_manager.immortal_killer.start_persistent_kill(ip, port, file_path)
    else:
        success, msg = ssh_manager.immortal_killer.stop_persistent_kill(ip, port, file_path)
        
    return jsonify({'status': 'ok' if success else 'error', 'message': msg})

@bp.route('/api/defense/immortal/kill_status', methods=['POST'])
def api_kill_status():
    data = request.json
    status = ssh_manager.immortal_killer.get_persistent_status(data['ip'], data.get('port', 22), data['file'])
    return jsonify({'active': status})
@bp.route('/api/defense/immortal/killers', methods=['GET'])
def api_get_active_killers_list():
    killers = ssh_manager.immortal_killer.get_active_killers()
    return jsonify({'killers': killers})

@bp.route('/api/defense/monitor/logs', methods=['GET'])
def api_get_monitor_logs():
    """获取最近的监控日志"""
    # monitor is exposed in ssh_manager facade? Yes, self.monitor
    if hasattr(ssh_manager, 'monitor') and ssh_manager.monitor:
        # Reverse to show newest first
        return jsonify({'logs': list(reversed(ssh_manager.monitor.logs))})
    return jsonify({'logs': []})

@bp.route('/api/defense/monitor/alerts', methods=['GET'])
def api_get_monitor_alerts():
    """获取历史告警"""
    alerts_file = os.path.join(current_app.config['DATA_DIR'], 'monitor_alerts.json')
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
                return jsonify({'alerts': list(reversed(alerts))})
        except: pass
    return jsonify({'alerts': []})


# ==================== Agent 探针管理 API ====================

@bp.route('/api/agent/deploy', methods=['POST'])
def api_deploy_agent():
    """部署Agent到指定靶机"""
    data = request.json
    ip = data.get('ip')
    port = int(data.get('port', 22))
    watch_dir = data.get('watch_dir', '/var/www/html')
    
    def _deploy():
        success, msg = ssh_manager.deploy_agent(ip, port, watch_dir)
        # 部署成功后自动启动Agent模式监控
        if success:
            ssh_manager.set_immortal_mode(ip, port, 'agent')
    
    threading.Thread(target=_deploy).start()
    return jsonify({'status': 'ok', 'message': f'Agent部署已启动: {ip}:{port}'})

@bp.route('/api/agent/stop', methods=['POST'])
def api_stop_agent():
    """停止靶机上的Agent"""
    data = request.json
    ip = data.get('ip')
    port = int(data.get('port', 22))
    
    success, msg = ssh_manager.stop_agent(ip, port)
    return jsonify({'status': 'ok' if success else 'error', 'message': msg})

@bp.route('/api/agent/status', methods=['POST'])
def api_get_agent_status():
    """获取Agent状态"""
    data = request.json
    ip = data.get('ip')
    port = int(data.get('port', 22))
    
    status = ssh_manager.get_agent_status(ip, port)
    health = ssh_manager.get_agent_health_status(ip, port)
    mode = ssh_manager.get_immortal_mode(ip, port)
    
    return jsonify({
        'status': status,
        'health': health,
        'mode': mode
    })

@bp.route('/api/agent/batch_deploy', methods=['POST'])
def api_batch_deploy_agent():
    """批量部署Agent到所有已连接靶机"""
    data = request.json or {}
    watch_dir = data.get('watch_dir', '/var/www/html')
    
    def _batch_deploy():
        results = ssh_manager.batch_deploy_agents(watch_dir)
        # 自动设置Agent模式
        for result in results:
            if result.get('success'):
                ssh_manager.set_immortal_mode(result['ip'], result['port'], 'agent')
        logger.info(f"Batch deploy completed: {len([r for r in results if r.get('success')])}/{len(results)} success")
    
    threading.Thread(target=_batch_deploy).start()
    return jsonify({'status': 'ok', 'message': '批量部署已启动'})

@bp.route('/api/agent/batch_stop', methods=['POST'])
def api_batch_stop_agent():
    """批量停止所有Agent"""
    results = ssh_manager.batch_stop_agents()
    return jsonify({'status': 'ok', 'results': results})

@bp.route('/api/agent/all_status', methods=['GET'])
def api_get_all_agent_status():
    """获取所有靶机的Agent状态"""
    statuses = ssh_manager.get_all_agent_status()
    health_map = ssh_manager.get_all_agents_health()
    
    # 合并状态
    result = {}
    for key, status in statuses.items():
        ip, port = key
        result[f"{ip}:{port}"] = {
            **status,
            'health': health_map.get(key, {}),
            'mode': ssh_manager.get_immortal_mode(ip, port)
        }
    
    return jsonify({'agents': result})

@bp.route('/api/agent/listener_stats', methods=['GET'])
def api_get_listener_stats():
    """获取Agent监听器统计"""
    stats = ssh_manager.get_listener_stats()
    return jsonify({'stats': stats})

@bp.route('/api/agent/immortal_stats', methods=['GET'])
def api_get_immortal_stats():
    """获取不死马查杀统计"""
    stats = ssh_manager.get_immortal_stats()
    return jsonify({'stats': stats})

@bp.route('/api/agent/set_mode', methods=['POST'])
def api_set_immortal_mode():
    """设置查杀模式 (agent/ssh/hybrid)"""
    data = request.json
    ip = data.get('ip')
    port = int(data.get('port', 22))
    mode = data.get('mode', 'hybrid')
    
    ssh_manager.set_immortal_mode(ip, port, mode)
    return jsonify({'status': 'ok', 'message': f'模式已设置为: {mode}'})

@bp.route('/api/agent/auto_deploy', methods=['GET'])
def api_get_auto_deploy_config():
    """获取自动部署配置"""
    return jsonify({
        'auto_deploy': ssh_manager.auto_deploy_agent,
        'auto_start_monitor': ssh_manager.agent_auto_start_monitor,
        'watch_dir': ssh_manager.agent_watch_dir
    })

@bp.route('/api/agent/auto_deploy', methods=['POST'])
def api_set_auto_deploy_config():
    """设置自动部署配置"""
    data = request.json
    if 'auto_deploy' in data:
        ssh_manager.auto_deploy_agent = data['auto_deploy']
    if 'auto_start_monitor' in data:
        ssh_manager.agent_auto_start_monitor = data['auto_start_monitor']
    if 'watch_dir' in data:
        ssh_manager.agent_watch_dir = data['watch_dir']
    
    return jsonify({
        'status': 'ok',
        'config': {
            'auto_deploy': ssh_manager.auto_deploy_agent,
            'auto_start_monitor': ssh_manager.agent_auto_start_monitor,
            'watch_dir': ssh_manager.agent_watch_dir
        }
    })

@bp.route('/api/agent/batch_action', methods=['POST'])
def api_agent_batch_action():
    """批量Agent操作"""
    data = request.json or {}
    action = data.get('action')  # 'deploy', 'stop', 'start_monitor', 'stop_monitor'
    targets = data.get('targets', [])  # [{'ip': 'x.x.x.x', 'port': 22}, ...]
    
    results = []
    
    def process_target(target_info):
        ip = target_info.get('ip')
        port = int(target_info.get('port', 22))
        
        try:
            if action == 'deploy':
                success, msg = ssh_manager.deploy_agent(ip, port)
                if success:
                    ssh_manager.set_immortal_mode(ip, port, 'agent')
                return {'ip': ip, 'port': port, 'success': success, 'message': msg}
            
            elif action == 'stop':
                success, msg = ssh_manager.stop_agent(ip, port)
                return {'ip': ip, 'port': port, 'success': success, 'message': msg}
            
            elif action == 'start_monitor':
                ssh_manager.start_immortal_killer(ip, port)
                return {'ip': ip, 'port': port, 'success': True, 'message': 'Monitor started'}
            
            elif action == 'stop_monitor':
                ssh_manager.stop_immortal_killer(ip, port)
                return {'ip': ip, 'port': port, 'success': True, 'message': 'Monitor stopped'}
            
            else:
                return {'ip': ip, 'port': port, 'success': False, 'message': f'Unknown action: {action}'}
        except Exception as e:
            return {'ip': ip, 'port': port, 'success': False, 'message': str(e)}
    
    # 如果没有指定targets，对所有已连接靶机执行
    if not targets:
        targets = [
            {'ip': t['ip'], 'port': t['port']} 
            for t in ssh_manager.targets 
            if t.get('status') == 'connected'
        ]
    
    # 并发执行
    import threading
    threads = []
    results_lock = threading.Lock()
    
    def worker(t):
        result = process_target(t)
        with results_lock:
            results.append(result)
    
    for t in targets:
        th = threading.Thread(target=worker, args=(t,))
        threads.append(th)
        th.start()
    
    for th in threads:
        th.join(timeout=30)
    
    return jsonify({
        'status': 'ok',
        'action': action,
        'total': len(targets),
        'success': len([r for r in results if r.get('success')]),
        'results': results
    })
