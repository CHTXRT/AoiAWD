import logging
import sys

# ANSI Colors
class Colors:
    RESET = "\033[0m"
    GREY = "\033[90m"
    WHITE = "\033[97m"
    green = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD_RED = "\033[41m\033[97m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with colors and simplified format.
    Format: [HH:MM:SS] [LEVEL] [Module] Message
    """
    
    FORMAT = "[%(asctime)s] [{level_color}%(levelname)s{reset}] [{module_color}%(name)s{reset}] %(message)s"
    DATE_FMT = "%H:%M:%S"

    LEVEL_COLORS = {
        logging.DEBUG: Colors.GREY,
        logging.INFO: Colors.green,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BOLD_RED
    }

    # 模块颜色映射
    MODULE_COLORS = {
        'SSHController': Colors.BLUE,
        'Connection': Colors.CYAN,
        'Defense': Colors.green,
        'AttackManager': Colors.RED,
        'SecurityScanner': Colors.YELLOW,
        'Immortal': Colors.BOLD_RED,
        'AgentDeployer': Colors.CYAN,
        'AgentListener': Colors.CYAN,
        'Monitor': Colors.green,
        'TargetManager': Colors.WHITE,
        'System': Colors.BLUE,
        'HTTP': Colors.GREY,
        'WS': Colors.GREY,
    }

    def format(self, record):
        level_color = self.LEVEL_COLORS.get(record.levelno, Colors.WHITE)
        
        # 简化模块名称并应用颜色
        module_name = record.name
        if record.name.startswith('werkzeug'):
            module_name = 'HTTP'
        elif record.name.startswith('socketio') or record.name.startswith('engineio'):
            module_name = 'WS'
        elif record.name == 'root':
            module_name = 'System'
        
        # 获取模块颜色
        module_color = self.MODULE_COLORS.get(module_name, Colors.CYAN)
        
        # 格式化模块名（固定宽度）
        module_name = module_name[:15]  # 截断过长名称
        
        # 临时替换 record.name 用于格式化
        original_name = record.name
        record.name = module_name
        
        # Apply colors
        formatter = logging.Formatter(
            self.FORMAT.format(
                level_color=level_color,
                module_color=module_color,
                reset=Colors.RESET
            ),
            datefmt=self.DATE_FMT
        )
        result = formatter.format(record)
        
        # 恢复原始名称
        record.name = original_name
        return result

# Windows Console Color Support
if sys.platform == 'win32':
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

_logger_initialized = False

def setup_logger():
    """
    Setup the root logger with ColoredFormatter for stderr
    and a standard FileHandler for file logs.
    """
    global _logger_initialized
    root_logger = logging.getLogger()
    
    # Avoid re-initialization if already setup (unless force re-setup is needed, but usually not)
    # Check if we already have our ColoredFormatter to be sure
    has_colored = any(isinstance(h, logging.StreamHandler) and isinstance(h.formatter, ColoredFormatter) for h in root_logger.handlers)
    
    # If we have colored handler, we are good.
    if has_colored:
        return root_logger
    
    _logger_initialized = True
    
    # 1. Clear existing handlers
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
    root_logger.setLevel(logging.INFO)
    
    # 2. Console Handler (Colored) - Use sys.stderr to play nice with other tools
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(ColoredFormatter())
    root_logger.addHandler(console_handler)
    
    # 3. Suppress & Hijack Noisy Libraries
    # These libraries often add their own handlers. We process them to:
    # - Remove their handlers
    # - Enable propagation to Root (so they use our ColoredFormatter)
    # - Set Level to WARNING to hide normal request logs
    libs = ['werkzeug', 'socketio', 'engineio', 'paramiko', 'urllib3', 'requests']
    for lib_name in libs:
        lib_logger = logging.getLogger(lib_name)
        lib_logger.handlers = []  # Force remove handlers
        lib_logger.propagate = True
        lib_logger.setLevel(logging.WARNING) # Hide INFO logs (like GET / 200)

    return root_logger

def add_file_handler(logger, log_file):
    """
    Add a file handler to the logger.
    """
    # Check if FileHandler already exists to avoid duplicates
    for h in logger.handlers:
        if isinstance(h, logging.FileHandler):
            # Check if it points to the same file? (Hard to verify path exactly, but assume singular file handler)
            return

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
