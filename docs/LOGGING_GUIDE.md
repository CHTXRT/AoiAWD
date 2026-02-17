# AWD-Defender 日志规范

## 概述

本文档定义了 AWD-Defender 项目的日志使用规范，确保日志输出统一、可读、可维护。

## 日志级别使用规范

| 级别 | 使用场景 | 示例 |
|------|---------|------|
| **DEBUG** | 详细调试信息，仅在开发时使用 | `logger.debug(f"Processing file: {filepath}")` |
| **INFO** | 正常操作信息 | `logger.info(f"Connected to {ip}:{port}")` |
| **WARNING** | 警告信息，不影响主要功能 | `logger.warning(f"Backup file missing, recreating...")` |
| **ERROR** | 错误信息，功能受损 | `logger.error(f"Connection failed: {e}")` |
| **CRITICAL** | 严重错误，系统可能崩溃 | `logger.critical("Out of memory!")` |

## Logger 命名规范

所有模块必须使用统一的 logger 命名，采用**大驼峰命名法**：

```python
# 正确示例
logger = logging.getLogger('Defense')
logger = logging.getLogger('AttackManager')
logger = logging.getLogger('AgentDeployer');

# 错误示例
logger = logging.getLogger('defense')  # 小写
logger = logging.getLogger(__name__)    # 使用模块路径
```

### 现有 Logger 名称列表

| 模块 | Logger 名称 | 颜色 |
|------|------------|------|
| `services/__init__.py` | `SSHController` | 蓝色 |
| `services/core/connection_manager.py` | `Connection` | 青色 |
| `services/core/target_manager.py` | `TargetManager` | 白色 |
| `services/defense_manager.py` | `Defense` | 绿色 |
| `services/attack_manager.py` | `AttackManager` | 红色 |
| `services/security_scanner.py` | `SecurityScanner` | 黄色 |
| `services/immortal_shell_killer.py` | `Immortal` | 粗红 |
| `services/monitor_service.py` | `Monitor` | 绿色 |
| `services/agent_deployer.py` | `AgentDeployer` | 青色 |
| `services/agent_listener.py` | `AgentListener` | 青色 |

## 日志格式规范

### 输出格式

```
[HH:MM:SS] [LEVEL] [Module] Message
```

示例：
```
[18:46:48] [INFO] [Connection] Connected to 127.0.0.1:18895 successfully
[18:46:49] [WARN] [Defense] Backup file missing, recreating...
[18:47:01] [ERROR] [AgentDeployer] Agent deployment failed: No binary found
```

### 消息格式

1. **包含目标标识**：涉及特定靶机的日志应包含 `[ip:port]` 前缀
   ```python
   logger.info(f"[{ip}:{port}] Starting backup...")
   ```

2. **简洁明了**：避免过长消息，关键信息前置
   ```python
   # 推荐
   logger.info(f"[{ip}:{port}] Backup completed. Files: {count}, Size: {size}MB")
   
   # 不推荐
   logger.info(f"The backup operation for target {ip}:{port} has been completed successfully. Total files backed up: {count}")
   ```

3. **异常记录**：记录异常时包含具体错误信息
   ```python
   try:
       result = operation()
   except Exception as e:
       logger.error(f"[{ip}:{port}] Operation failed: {e}")
   ```

## 代码规范

### 1. Logger 初始化

在每个模块文件顶部初始化 logger：

```python
import logging

logger = logging.getLogger('ModuleName')
# 不需要设置 level，统一由根 logger 控制
```

### 2. 禁止使用 print

**所有输出必须使用 logger**，禁止使用 `print()`：

```python
# 正确
logger.info("Starting service...")

# 错误
print("Starting service...")
```

### 3. 日志级别选择

```python
# DEBUG - 详细调试信息
logger.debug(f"Processing item {i}: {item}")

# INFO - 正常操作
logger.info(f"[{ip}:{port}] Connected successfully")

# WARNING - 警告但不影响功能
logger.warning(f"[{ip}:{port}] Agent not found, using fallback")

# ERROR - 功能错误
logger.error(f"[{ip}:{port}] Connection failed: {e}")

# CRITICAL - 系统级错误
logger.critical("System out of memory!")
```

### 4. 批量操作日志

批量操作应记录总体进度，避免每条记录都输出：

```python
# 推荐
logger.info(f"Starting batch deploy to {len(targets)} targets...")
success = 0
for target in targets:
    if deploy(target):
        success += 1
logger.info(f"Batch deploy completed: {success}/{len(targets)} success")

# 不推荐（每条记录都输出）
for target in targets:
    logger.info(f"Deploying to {target}...")  # 太频繁
    deploy(target)
```

## 配置文件

日志相关配置在 `app/config.py`：

```python
# 日志级别设置（未来可扩展）
LOG_LEVEL = logging.INFO
LOG_FORMAT = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
```

## 日志文件

- **控制台输出**：彩色格式化输出到 stderr
- **文件输出**：位于 `data/logs/flask.log`，包含完整时间戳和详细信息

## 示例代码

```python
import logging

logger = logging.getLogger('Defense')

class DefenseManager:
    def backup_target(self, ip, port):
        logger.info(f"[{ip}:{port}] Starting backup...")
        
        try:
            # 检查现有备份
            if backup_exists:
                logger.info(f"[{ip}:{port}] Backup already exists, skipping")
                return True
            
            # 执行备份
            result = perform_backup()
            logger.info(f"[{ip}:{port}] Backup completed. Size: {result.size}MB")
            return True
            
        except Exception as e:
            logger.error(f"[{ip}:{port}] Backup failed: {e}")
            return False
```

## 检查清单

添加新模块时，请检查：

- [ ] 模块顶部导入并初始化 logger
- [ ] Logger 名称使用大驼峰命名
- [ ] 所有 print 语句替换为 logger
- [ ] 涉及靶机的日志包含 `[ip:port]` 前缀
- [ ] 异常处理记录错误日志
- [ ] 批量操作记录总体进度而非每条记录
