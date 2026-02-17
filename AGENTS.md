# AWD-Defender 项目指南

本文档为 AI 编程助手提供项目背景、架构和开发指南。

## 项目概述

AWD-Defender 是专为 AWD (Attack With Defense) 竞赛设计的自动化防御与反制平台。它集成了资产管理、漏洞扫描、权限维持、流量监控和自动化反击等核心功能，帮助选手高效管理多台靶机，快速发现并利用漏洞。

**主要功能模块：**
- **资产防御与管理**: SSH 批量管理、Webshell 扫描、www-data 权限维持、实时文件监控
- **自动化反制**: 自动特征提取、网段遍历攻击、Payload 投递、不死马植入
- **便捷工具**: 文件上传/下载、批量命令执行、定时任务、Pwn 题目自动化 Patch

## 技术栈

- **后端框架**: Flask (Python 3.8+)
- **实时通信**: Flask-SocketIO
- **SSH 连接**: Paramiko
- **前端**: 原生 JavaScript + Socket.IO Client + CSS Modules
- **数据存储**: JSON 文件 (无数据库)
- **日志**: 自定义彩色日志系统

## 依赖安装

```bash
pip install -r requirements.txt
```

依赖列表 (`requirements.txt`):
- Flask
- flask_socketio
- paramiko
- Requests
- Werkzeug

## 项目结构

```
AWD-Defender/
├── main.py                     # 应用启动入口
├── diagnose.py                 # 环境诊断工具
├── requirements.txt            # Python 依赖
├── .gitignore                  # Git 忽略规则
│
├── app/                        # 主应用目录
│   ├── __init__.py             # Flask 应用工厂函数
│   ├── config.py               # 全局配置类
│   ├── routes/                 # Web 路由 (Flask Blueprint)
│   │   ├── __init__.py         # Blueprint 定义
│   │   ├── index.py            # 主页路由
│   │   ├── auth.py             # 登录认证
│   │   ├── ssh.py              # SSH 操作接口
│   │   ├── files.py            # 文件管理接口
│   │   ├── attack.py           # 攻击管理接口
│   │   ├── defense.py          # 防御管理接口
│   │   ├── rules.py            # 扫描规则管理
│   │   ├── keys.py             # SSH 密钥管理
│   │   └── sockets.py          # WebSocket 事件处理
│   ├── services/               # 核心服务层
│   │   ├── __init__.py         # SSHControllerFacade 外观类
│   │   ├── core/               # 核心管理器
│   │   │   ├── target_manager.py    # 靶机管理
│   │   │   ├── key_manager.py       # SSH 密钥管理
│   │   │   └── connection_manager.py # SSH 连接管理
│   │   ├── security_scanner.py      # 安全扫描器
│   │   ├── defense_manager.py       # 防御管理器
│   │   ├── attack_manager.py        # 攻击管理器
│   │   ├── monitor_service.py       # 监控服务
│   │   └── immortal_shell_killer.py # 不死马查杀
│   ├── template/               # HTML 模板
│   ├── static/                 # 静态资源
│   │   ├── css/modules/        # CSS 模块化文件
│   │   └── js/modules/         # JS 模块化文件
│   └── utils/                  # 工具函数
│       ├── logger.py           # 彩色日志系统
│       └── xshell.py           # Xshell 集成
│
├── data/                       # 数据存储目录
│   ├── targets.json            # 靶机配置数据
│   ├── backups/                # 文件备份目录
│   ├── logs/                   # 日志目录
│   ├── uploads/                # 上传文件目录
│   ├── xshell/                 # Xshell 会话文件
│   └── *.json                  # 各种状态文件
│
├── keys/                       # SSH 私钥存储
├── tools/                      # 辅助工具
│   ├── evilPatcher/            # Pwn 题目 Patch 工具
│   ├── aoi/                    # AOI 监控工具
│   ├── py_guard.py             # Python 文件监控探针
│   └── ...
│
└── tests/                      # 测试目录
    └── test_ssh_concurrency.py # SSH 并发测试
```

## 启动与运行

### 启动应用

```bash
python main.py
```

启动时控制台会显示随机生成的 `AWD TEAM TOKEN`，请妥善保管。默认访问地址: `http://localhost:8080`

### 环境诊断

如果遇到运行问题，可以使用诊断工具：

```bash
python diagnose.py
```

## 架构设计

### 1. 分层架构

- **路由层** (`app/routes/`): 处理 HTTP 请求和 WebSocket 事件
- **服务层** (`app/services/`): 核心业务逻辑
- **核心层** (`app/services/core/`): 底层管理器 (靶机、密钥、连接)
- **工具层** (`app/utils/`): 通用工具函数

### 2. 外观模式 (Facade Pattern)

`SSHControllerFacade` 类 (`app/services/__init__.py`) 作为统一入口，整合所有服务：

```python
ssh_manager = SSHControllerFacade()
# 使用示例
ssh_manager.add_target(ip, port, user, password)
ssh_manager.connect(ip, port)
ssh_manager.execute(ip, port, command)
```

### 3. 数据流

1. **靶机数据**: 存储在 `data/targets.json`，启动时加载
2. **实时更新**: 通过 Socket.IO 向前端推送状态变更
3. **日志记录**: 同时输出到控制台 (彩色) 和文件

## 关键配置

配置文件位于 `app/config.py`，包含：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `BASE_DIR` | 项目根目录 | 自动检测 |
| `DATA_DIR` | 数据目录 | `data/` |
| `UPLOAD_FOLDER` | 上传目录 | `data/uploads/` |
| `KEYS_FOLDER` | SSH 密钥目录 | `keys/` |
| `TARGETS_FILE` | 靶机数据文件 | `data/targets.json` |
| `TEAM_TOKEN` | 访问令牌 | 环境变量或随机生成 |

**环境变量：**
- `AWD_TEAM_TOKEN`: 设置访问令牌
- `SECRET_KEY`: Flask 密钥

## 代码风格指南

### 命名规范

- **文件名**: 小写，下划线分隔 (如 `target_manager.py`)
- **类名**: 大驼峰 (如 `TargetManager`)
- **函数/变量**: 小写，下划线分隔 (如 `add_target`)
- **常量**: 大写，下划线分隔

### 注释规范

- 使用中文注释，与项目保持一致
- 关键逻辑添加行内注释
- 类和函数添加 docstring (如有必要)

### 日志规范

```python
import logging
logger = logging.getLogger('ModuleName')

# 使用示例
logger.info(f"已加载 {count} 个靶机")
logger.warning("连接超时")
logger.error(f"执行失败: {e}")
```

### 线程安全

- 共享数据使用 `threading.RLock()` 保护
- SSH 连接使用信号量限制并发通道数

## 开发指南

### 添加新的路由

1. 在 `app/routes/` 创建新文件或添加到现有文件
2. 从 `.` 导入 `bp` Blueprint
3. 使用 `@bp.route()` 装饰器定义路由

```python
from . import bp

@bp.route('/api/example', methods=['GET'])
def example():
    return {'status': 'ok'}
```

### 添加新的服务

1. 在 `app/services/` 创建服务类
2. 在 `SSHControllerFacade` 中初始化并添加委托方法
3. 通过 `ssh_manager` 访问

### WebSocket 事件

在 `app/routes/sockets.py` 中注册事件：

```python
def register_socketio_events(socketio):
    @socketio.on('custom_event')
    def handle_custom(data):
        emit('response', {'data': 'ok'})
```

## 测试

当前项目测试覆盖有限，主要测试文件：

```bash
# SSH 并发测试
python tests/test_ssh_concurrency.py
```

**建议**：新增功能时添加相应的单元测试。

## 安全注意事项

1. **TEAM TOKEN**: 启动时生成的令牌用于身份验证，请妥善保管
2. **密码存储**: 靶机密码以明文存储在 `data/targets.json`，注意文件权限
3. **SSH 密钥**: 存储在 `keys/` 目录，确保目录权限安全
4. **代码注入**: 执行远程命令时注意过滤，防止命令注入

## 常用文件说明

| 文件 | 用途 |
|------|------|
| `data/targets.json` | 靶机配置列表 |
| `data/local_ip.txt` | 回连 IP 配置 |
| `data/immortal_alerts.json` | 不死马告警记录 |
| `data/monitor_alerts.json` | 文件监控告警 |
| `data/logs/flask.log` | 应用日志 |
| `tools/py_guard.py` | 文件监控探针 (部署到靶机) |

## 部署说明

1. 确保 Python 3.8+ 环境
2. 安装依赖: `pip install -r requirements.txt`
3. 创建必要目录: `keys/`, `data/` 及其子目录
4. 运行诊断: `python diagnose.py`
5. 启动应用: `python main.py`
6. 访问 `http://localhost:8080`，使用显示的 TOKEN 登录

## 扩展开发

### 添加新的扫描规则

编辑 `app/services/security_scanner.py`，在 `custom_rules` 中添加规则。

### 添加新的攻击 Payload

编辑 `app/services/attack_manager.py`，修改攻击逻辑。

### 集成新的工具

1. 将工具放入 `tools/` 目录
2. 在 `app/services/defense_manager.py` 中添加调用逻辑
3. 添加前端界面调用接口

---

**注意**: 本工具仅供 AWD 竞赛防御训练与授权安全测试使用。严禁用于未授权的非法攻击。
