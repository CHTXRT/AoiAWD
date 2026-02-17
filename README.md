# AWD-Defender 控制台

AWD-Defender 是专为 AWD (Attack With Defense) 竞赛设计的自动化防御与反制平台。它集成了资产管理、漏洞扫描、权限维持、流量监控和自动化反击等核心功能，旨在帮助选手高效管理多台靶机，快速发现并利用漏洞。

## 🚀 核心功能 (Core Features)

### 1. 🛡️ 资产防御与管理 (Defense & Management)
*   **SSH 批量管理**: 快速连接、断开、检测所有靶机的 SSH 连接状态。
*   **Webshell 扫描增强**: 
    *   基于正则匹配 (`grep`) 和文件快照 (`Snapshot`) 技术，自动发现新增的 PHP 后门文件。
    *   **智能误报剔除**: 深度识别防御代码（如 WAF、`include_once`）和 AOI 工具签名，避免误杀合法防御脚本。
    *   **全编码支持**: 兼容二进制或乱码文件的扫描，防止因编码问题导致的检测遗漏或误报。
*   **www-data 权限维持**: 
    *   自动检测 `www-data` 用户权限，并尝试通过 `/tmp` 目录下的 SUID shell (`mujica`) 提权。
    *   **Xshell 集成**: 支持一键启动 Xshell 连接到靶机。
        *   **智能启动**: 本机访问时直接启动 Xshell；远程访问时自动复制 SSH 命令。
        *   **提权辅助**: 自动复制提权命令 (`/tmp/mujica -p`)，方便快速获取 Shell。
*   **实时文件监控 (File Monitor)**:
    *   **PyGuard Agent**: 自动部署轻量级 Python 监控探针 (`py_guard.py`)，基于 `inotify` 实时监控文件变动。
    *   **即时告警**: 文件创建、修改、删除操作毫秒级上报，配合 Socket.IO 实现前端实时弹窗告警。
*   **智能回连 IP 管理**:
    *   **独立配置**: 支持为每台靶机单独设置回连 IP (Local IP)，适应复杂的网络环境（如多网卡、VPN、内网穿透）。
    *   **自动探测**: 若未配置，系统会自动探测 SSH 连接使用的本机 IP，实现零配置部署，并在前端直观显示探测结果。
*   **AOI 工具部署**: 一键部署 `tapeworm`  和 `roundworm` (系统监控) 工具，自动适配回连 IP。
*   **EvilPatcher 集成**: 支持 Pwn 题目的自动化 Patch。
    *   **智能降级**: 在 Windows 环境下，如检测到缺失 Linux 环境，将尝试通过 WSL 运行补丁工具。
    *   **自动备份**: Patch 前自动备份原始二进制文件，支持一键还原。

### 2. ⚔️ 自动化反制 (Auto-Counter Attack)
当自身靶机被攻击或发现 Webshell 时，系统会自动触发反制流程：
*   **自动特征提取**: 识别 Webshell 路径和连接密码。
*   **本地验证**: 
    *   优先在本地环境验证 Webshell 可用性。
    *   **动态端口识别**: 自动识别 Web 服务端口 (80/8080/SSH端口)，确保利用成功率。
*   **自动化攻击**:
    *   **网段遍历**: 根据配置的网段模板 (如 `172.16.{x}.101`) 自动攻击同网段的其他队伍。
    *   **精确打击**: 支持直接输入 **IP 列表** (如 `10.0.1.5,10.0.1.6`) 进行点对点攻击。
*   **Payload 投递**: 自动植入 **不死马 (Undead Shell)**，并尝试维持控制权限。
*   **实时战况**: 提供实时攻击日志面板，支持手动刷新战况。

### 3. 🛠️ 便捷工具 (Utilities)
*   **文件上传/下载**: 支持通过 Web 界面直接上传文件到靶机或下载文件。
*   **批量命令执行**: 支持对所有选定靶机批量执行 Shell 命令。
*   **定时任务**: 支持设置定时任务 (如定时清理 `/tmp` 目录)。

## 📦 安装与运行 (Installation & Usage)

### 环境要求
*   Python 3.8+
*   Flask, Paramiko, Requests, Flask-SocketIO

### 安装依赖
```bash
pip install -r requirements.txt
```

### 启动平台
```bash
python main.py
```
*   **Security Notice**: 启动时控制台会显示随机生成的 `AWD TEAM TOKEN`，请妥善保管。
*   默认访问地址: `http://localhost:8080`
*   默认 SSH 私钥存放目录: `keys/`

### 环境诊断
如果遇到运行问题，可以使用自带的诊断工具检查环境：
```bash
python diagnose.py
```

## ⚙️ 配置说明 (Configuration)

### 靶机列表 (`data/targets.json`)
平台启动时会自动加载 `data/targets.json`。你也可以在 Web 界面手动添加靶机。
```json
{
    "172.16.1.101": {
        "ip": "172.16.1.101",
        "port": 22,
        "user": "root",
        "password": "password",
        "key_file": null,
        "local_ip": "192.168.1.5"
    }
}
```

### 攻击配置
在 Web 界面的 "Target Network Template" 中配置：
*   **网段模式**: `172.16.{x}.101` (系统会自动替换 `{x}` 为 1-254)
*   **列表模式**: `172.16.2.101, 172.16.3.101` (逗号分隔的特定 IP)

## 📝 目录结构
```
AWD-Defender/
├── app/
│   ├── routes/             # Web 路由模块化目录
│   ├── services/           # 核心服务 (SSH, Attack, Defense, Scanner)
│   ├── template/           # 前端模板 (HTML/JS)
│   └── config.py           # 配置文件
├── data/
│   ├── backups/            # 靶机文件备份与 Patch 备份
│   ├── logs/               # 系统与攻击日志
│   └── targets.json        # 靶机配置数据
├── keys/                   # SSH 私钥存储
├── tools/                  # 辅助工具 (AOI Tools, EvilPatcher)
├── main.py                 # 启动入口脚本
├── diagnose.py             # 环境诊断脚本
└── requirements.txt        # 依赖列表
```

## ⚠️ 免责声明
本工具仅供 **AWD 竞赛防御训练** 与 **授权安全测试** 使用。严禁用于未授权的非法攻击，否则后果自负。
