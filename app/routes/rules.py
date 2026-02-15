from flask import request, jsonify
from app.services import ssh_manager
from . import bp

@bp.route('/api/rules', methods=['GET'])
def api_get_rules():
    """获取所有自定义 PHP 规则"""
    return jsonify({'rules': ssh_manager.get_custom_rules()})

@bp.route('/api/rules/add', methods=['POST'])
def api_add_rule():
    """添加自定义 PHP 规则"""
    data = request.json
    name = data.get('name', '')
    pattern = data.get('pattern', '')
    desc = data.get('description', '')
    if not name or not pattern:
        return jsonify({'error': '名称和正则表达式不能为空'}), 400
    rule = ssh_manager.add_custom_rule(name, pattern, desc)
    return jsonify({'status': 'ok', 'rule': rule})

@bp.route('/api/rules/remove', methods=['POST'])
def api_remove_rule():
    """移除自定义 PHP 规则"""
    data = request.json
    index = data.get('index', -1)
    removed = ssh_manager.remove_custom_rule(int(index))
    if removed:
        return jsonify({'status': 'ok', 'removed': removed})
    return jsonify({'error': '规则不存在'}), 404

@bp.route('/api/rules/toggle', methods=['POST'])
def api_toggle_rule():
    """启用/禁用自定义 PHP 规则"""
    data = request.json
    index = data.get('index', -1)
    rule = ssh_manager.toggle_custom_rule(int(index))
    if rule:
        return jsonify({'status': 'ok', 'rule': rule})
    return jsonify({'error': '规则不存在'}), 404
