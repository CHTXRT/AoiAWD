import sys
import os
import subprocess
import threading
import re

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                 QTextEdit, QTabWidget, QFileDialog, QMessageBox, 
                                 QGroupBox, QGridLayout, QStyleFactory, QTableWidget, 
                                 QTableWidgetItem, QHeaderView, QAbstractItemView)
    from PyQt5.QtCore import Qt, pyqtSignal
    from PyQt5.QtGui import QFont, QPalette, QColor, QBrush
except ImportError:
    print("Error: PyQt5 is not installed. Please install it using 'pip install PyQt5'")
    pass

# 尝试导入 pwntools
try:
    from pwn import ELF
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False

class PwnCheckApp(QMainWindow):
    # 定义信号用于线程通信
    update_status_signal = pyqtSignal(str)
    update_checksec_signal = pyqtSignal(dict)
    update_symbols_signal = pyqtSignal(list)
    update_gadgets_signal = pyqtSignal(list)
    update_ropchain_signal = pyqtSignal(str)
    update_string_search_signal = pyqtSignal(str)
    update_seccomp_signal = pyqtSignal(str)
    update_one_gadget_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.gadgets_data = []
        self.init_ui()
        self.apply_styles()
        
        # 启用拖拽
        self.setAcceptDrops(True)
        
        # 连接信号
        self.update_status_signal.connect(self.update_status)
        self.update_checksec_signal.connect(self.update_checksec_ui)
        self.update_symbols_signal.connect(self.update_symbols_ui)
        self.update_gadgets_signal.connect(self.update_gadgets_data)
        self.update_ropchain_signal.connect(self.update_ropchain_ui)
        self.update_string_search_signal.connect(self.update_string_search_ui)
        self.update_seccomp_signal.connect(self.update_seccomp_ui)
        self.update_one_gadget_signal.connect(self.update_one_gadget_ui)
        self.error_signal.connect(self.show_error)

    def init_ui(self):
        self.setWindowTitle("PWN Checksec & Gadget Tool")
        self.setGeometry(100, 100, 1100, 850)

        # 主窗口部件和布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(20)
        main_widget.setLayout(main_layout)

        # 选项卡控件
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 页面 1: Checksec
        self.tab1 = QWidget()
        self.setup_tab1()
        self.tabs.addTab(self.tab1, "🛡️ 基本信息")

        # 页面 2: Gadgets
        self.tab2 = QWidget()
        self.setup_tab2()
        self.tabs.addTab(self.tab2, "🔧 ROP Gadgets")
        
        # 页面 3: Seccomp
        self.tab3 = QWidget()
        self.setup_tab3()
        self.tabs.addTab(self.tab3, "🚫 Seccomp")
        
        # 页面 4: Libc 分析
        self.tab4 = QWidget()
        self.setup_tab4()
        self.tabs.addTab(self.tab4, "📚 Libc 分析")

        # 状态栏
        self.status_label = QLabel("就绪")
        self.statusBar().addWidget(self.status_label)

    def apply_styles(self):
        # 设置应用程序样式
        app = QApplication.instance()
        app.setStyle(QStyleFactory.create("Fusion"))
        
        # 设置默认字体
        font = QFont("Segoe UI", 10)
        app.setFont(font)

        # 全局样式表
        self.setStyleSheet("""
            /* Global */
            QMainWindow {
                background-color: #f4f6f9;
            }
            QWidget {
                color: #333;
            }
            
            /* Tabs */
            QTabWidget::pane {
                border: 1px solid #e1e4e8;
                background: white;
                border-radius: 8px;
                top: -1px; 
            }
            QTabBar::tab {
                background: #f6f8fa;
                border: 1px solid #e1e4e8;
                padding: 10px 24px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                color: #586069;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom-color: white;
                color: #0366d6;
            }
            QTabBar::tab:hover {
                background-color: #ffffff;
            }

            /* Buttons */
            QPushButton {
                background-color: #0366d6;
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #0255b3;
            }
            QPushButton:pressed {
                background-color: #024494;
            }
            
            /* Specific Button Colors */
            QPushButton[class="danger"] {
                background-color: #d73a49;
            }
            QPushButton[class="danger"]:hover {
                background-color: #cb2431;
            }
            QPushButton[class="success"] {
                background-color: #28a745;
            }
            QPushButton[class="success"]:hover {
                background-color: #218838;
            }
            QPushButton[class="warning"] {
                background-color: #f66a0a;
            }
            QPushButton[class="warning"]:hover {
                background-color: #d95b05;
            }
            QPushButton[class="secondary"] {
                background-color: #6c757d;
            }
            QPushButton[class="secondary"]:hover {
                background-color: #5a6268;
            }

            /* LineEdit */
            QLineEdit {
                border: 1px solid #e1e4e8;
                border-radius: 6px;
                padding: 8px 12px;
                background: white;
                selection-background-color: #0366d6;
            }
            QLineEdit:focus {
                border: 1px solid #0366d6;
                outline: none;
            }

            /* TextEdit */
            QTextEdit {
                border: 1px solid #e1e4e8;
                border-radius: 6px;
                background-color: #fcfcfc;
                selection-background-color: #0366d6;
                font-family: "Consolas", "Monaco", monospace;
                font-size: 13px;
                padding: 8px;
            }

            /* GroupBox */
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e1e4e8;
                border-radius: 8px;
                margin-top: 24px;
                background-color: white;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                left: 12px;
                color: #24292e;
                background-color: white; 
            }

            /* Table */
            QTableWidget {
                border: 1px solid #e1e4e8;
                border-radius: 6px;
                background-color: white;
                gridline-color: #f0f0f0;
                font-family: "Consolas", "Monaco", monospace;
                font-size: 13px;
                selection-background-color: #e6f3ff;
                selection-color: black;
            }
            QHeaderView::section {
                background-color: #f6f8fa;
                padding: 10px;
                border: none;
                border-bottom: 1px solid #e1e4e8;
                border-right: 1px solid #e1e4e8;
                font-weight: bold;
                color: #586069;
                font-family: "Segoe UI", sans-serif;
            }
            QTableWidget::item {
                padding: 6px;
            }
            
            /* Scrollbar */
            QScrollBar:vertical {
                border: none;
                background: #f1f1f1;
                width: 12px;
                margin: 0px;
                border-radius: 0px;
            }
            QScrollBar::handle:vertical {
                background: #c1c1c1;
                min-height: 20px;
                border-radius: 6px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background: #a8a8a8;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            /* StatusBar */
            QStatusBar {
                background-color: #ffffff;
                border-top: 1px solid #e1e4e8;
                color: #586069;
            }
        """)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if not files:
            return
        
        filepath = files[0]
        
        # 根据当前 Tab 判断填入哪里
        current_index = self.tabs.currentIndex()
        if current_index == 3: # Libc Tab (索引从0开始，0,1,2,3)
            self.libc_path_input.setText(filepath)
            self.status_label.setText(f"已加载 Libc 文件: {os.path.basename(filepath)}")
        else:
            self.path_input.setText(filepath)
            self.status_label.setText(f"已加载目标文件: {os.path.basename(filepath)}")
            # 如果不在第一页，自动跳转到第一页方便查看
            # self.tabs.setCurrentIndex(0) 

    def setup_tab1(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)
        self.tab1.setLayout(layout)

        # 顶部区域：文件选择和基本信息
        top_layout = QHBoxLayout()
        top_layout.setSpacing(24)
        
        # 左侧：文件选择
        file_group = QGroupBox("目标文件")
        file_layout = QVBoxLayout()
        file_layout.setContentsMargins(20, 25, 20, 20)
        file_layout.setSpacing(15)
        
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("选择二进制文件路径 (支持拖拽)...")
        path_layout.addWidget(self.path_input)
        
        btn_browse = QPushButton("📂")
        btn_browse.setFixedWidth(45)
        btn_browse.setProperty("class", "secondary")
        btn_browse.clicked.connect(self.browse_file)
        path_layout.addWidget(btn_browse)
        file_layout.addLayout(path_layout)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        btn_check = QPushButton("🚀 开始全面分析")
        btn_check.setProperty("class", "success")
        btn_check.clicked.connect(self.run_analysis)
        btn_layout.addWidget(btn_check)
        
        btn_clear = QPushButton("🗑️ 清除")
        btn_clear.setProperty("class", "danger")
        btn_clear.clicked.connect(self.clear_all)
        btn_layout.addWidget(btn_clear)
        
        file_layout.addLayout(btn_layout)
        
        file_group.setLayout(file_layout)
        top_layout.addWidget(file_group, 1)

        # 右侧：Checksec 结果
        checksec_group = QGroupBox("安全机制 (Checksec)")
        checksec_layout = QGridLayout()
        checksec_layout.setContentsMargins(20, 25, 20, 20)
        checksec_layout.setHorizontalSpacing(30)
        checksec_layout.setVerticalSpacing(15)
        
        self.result_labels = {}
        keys = ["架构", "RELRO", "Stack", "NX", "PIE"]
        
        for i, key in enumerate(keys):
            lbl_key = QLabel(f"{key}")
            lbl_key.setFont(QFont("Segoe UI", 10, QFont.Bold))
            lbl_key.setStyleSheet("color: #586069;")
            
            lbl_val = QLabel("-")
            lbl_val.setFont(QFont("Consolas", 11, QFont.Bold))
            lbl_val.setStyleSheet("color: #24292e;")
            
            checksec_layout.addWidget(lbl_key, i, 0)
            checksec_layout.addWidget(lbl_val, i, 1)
            
            self.result_labels[key] = lbl_val
            
        checksec_group.setLayout(checksec_layout)
        top_layout.addWidget(checksec_group, 1)
        
        layout.addLayout(top_layout)

        # 底部区域：符号表
        symbols_group = QGroupBox("符号表与导入函数")
        symbols_layout = QVBoxLayout()
        symbols_layout.setContentsMargins(15, 25, 15, 15)
        
        self.symbols_table = QTableWidget()
        self.symbols_table.setColumnCount(3)
        self.symbols_table.setHorizontalHeaderLabels(["类型", "名称", "地址"])
        self.symbols_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.symbols_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.symbols_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.symbols_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.symbols_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.symbols_table.setShowGrid(False)
        self.symbols_table.setAlternatingRowColors(True)
        self.symbols_table.verticalHeader().setVisible(False)
        
        symbols_layout.addWidget(self.symbols_table)
        symbols_group.setLayout(symbols_layout)
        
        layout.addWidget(symbols_group)

    def setup_tab2(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.tab2.setLayout(layout)
        
        # 创建子选项卡
        self.sub_tabs = QTabWidget()
        layout.addWidget(self.sub_tabs)
        
        # 子页 1: 所有 Gadgets
        self.sub_tab_gadgets = QWidget()
        self.setup_sub_tab_gadgets()
        self.sub_tabs.addTab(self.sub_tab_gadgets, "📋 所有 Gadgets")
        
        # 子页 2: ROP Chain
        self.sub_tab_ropchain = QWidget()
        self.setup_sub_tab_ropchain()
        self.sub_tabs.addTab(self.sub_tab_ropchain, "⛓️ ROP Chain")
        
        # 子页 3: 字符串搜索
        self.sub_tab_strings = QWidget()
        self.setup_sub_tab_strings()
        self.sub_tabs.addTab(self.sub_tab_strings, "🔍 字符串搜索")

    def setup_sub_tab_gadgets(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.sub_tab_gadgets.setLayout(layout)

        # 搜索框
        search_layout = QHBoxLayout()
        lbl = QLabel("本地筛选:")
        search_layout.addWidget(lbl)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入关键词筛选已加载的 Gadgets...")
        self.search_input.textChanged.connect(self.filter_gadgets)
        search_layout.addWidget(self.search_input)
        
        layout.addLayout(search_layout)

        # 表格显示区域
        self.gadget_table = QTableWidget()
        self.gadget_table.setColumnCount(2)
        self.gadget_table.setHorizontalHeaderLabels(["地址", "指令"])
        self.gadget_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.gadget_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.gadget_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.gadget_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.gadget_table.setAlternatingRowColors(True)
        self.gadget_table.setShowGrid(False)
        self.gadget_table.verticalHeader().setVisible(False)
        
        layout.addWidget(self.gadget_table)

    def setup_sub_tab_ropchain(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.sub_tab_ropchain.setLayout(layout)
        
        btn_layout = QHBoxLayout()
        btn_gen = QPushButton("⚡ 生成 ROP Chain")
        btn_gen.setProperty("class", "warning") # 使用 warning 样式 (橙色)
        btn_gen.clicked.connect(self.run_ropchain)
        btn_layout.addWidget(btn_gen)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.ropchain_text = QTextEdit()
        self.ropchain_text.setReadOnly(True)
        self.ropchain_text.setPlaceholderText("点击上方按钮生成 ROP Chain...")
        layout.addWidget(self.ropchain_text)

    def setup_sub_tab_strings(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.sub_tab_strings.setLayout(layout)
        
        search_layout = QHBoxLayout()
        lbl = QLabel("搜索字符串:")
        search_layout.addWidget(lbl)
        
        self.string_search_input = QLineEdit()
        self.string_search_input.setPlaceholderText("输入要搜索的字符串...")
        search_layout.addWidget(self.string_search_input)
        
        btn_search = QPushButton("🔎 搜索")
        btn_search.clicked.connect(self.run_string_search)
        search_layout.addWidget(btn_search)
        
        layout.addLayout(search_layout)
        
        self.strings_text = QTextEdit()
        self.strings_text.setReadOnly(True)
        self.strings_text.setPlaceholderText("搜索结果将显示在这里...")
        layout.addWidget(self.strings_text)

    def setup_tab3(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.tab3.setLayout(layout)
        
        btn_layout = QHBoxLayout()
        btn_seccomp = QPushButton("🛡️ 分析 Seccomp 规则")
        btn_seccomp.setProperty("class", "warning")
        btn_seccomp.clicked.connect(self.run_seccomp)
        btn_layout.addWidget(btn_seccomp)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.seccomp_text = QTextEdit()
        self.seccomp_text.setReadOnly(True)
        self.seccomp_text.setPlaceholderText("点击上方按钮分析 Seccomp 规则 (需要安装 seccomp-tools)...")
        layout.addWidget(self.seccomp_text)

    def setup_tab4(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        self.tab4.setLayout(layout)
        
        # Libc 文件选择
        file_layout = QHBoxLayout()
        self.libc_path_input = QLineEdit()
        self.libc_path_input.setPlaceholderText("选择 libc.so 文件路径 (支持拖拽)...")
        file_layout.addWidget(self.libc_path_input)
        
        btn_browse_libc = QPushButton("📂 选择 Libc...")
        btn_browse_libc.setProperty("class", "secondary")
        btn_browse_libc.clicked.connect(self.browse_libc_file)
        file_layout.addWidget(btn_browse_libc)
        
        btn_one_gadget = QPushButton("💥 查找 One Gadget")
        btn_one_gadget.setProperty("class", "danger")
        btn_one_gadget.clicked.connect(self.run_one_gadget)
        file_layout.addWidget(btn_one_gadget)
        
        layout.addLayout(file_layout)
        
        self.one_gadget_text = QTextEdit()
        self.one_gadget_text.setReadOnly(True)
        self.one_gadget_text.setPlaceholderText("One Gadget 结果将显示在这里 (需要安装 one_gadget)...")
        layout.addWidget(self.one_gadget_text)

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择二进制文件")
        if filename:
            self.path_input.setText(filename)

    def browse_libc_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择 Libc 文件")
        if filename:
            self.libc_path_input.setText(filename)

    def clear_all(self):
        # 清除所有输入和输出
        self.path_input.clear()
        self.libc_path_input.clear()
        
        # 重置 Checksec 结果
        for key, lbl in self.result_labels.items():
            lbl.setText("-")
            lbl.setStyleSheet("color: #24292e;")
            
        # 清除表格和文本框
        self.symbols_table.setRowCount(0)
        self.gadget_table.setRowCount(0)
        self.gadgets_data = []
        self.ropchain_text.clear()
        self.strings_text.clear()
        self.seccomp_text.clear()
        self.one_gadget_text.clear()
        self.search_input.clear()
        self.string_search_input.clear()
        
        self.status_label.setText("就绪")

    def run_analysis(self):
        filepath = self.path_input.text()
        if not self._validate_file(filepath):
            return

        # 启动后台线程进行分析
        thread = threading.Thread(target=self._analyze_thread, args=(filepath,), daemon=True)
        thread.start()

    def run_ropchain(self):
        filepath = self.path_input.text()
        if not self._validate_file(filepath):
            return
            
        self.ropchain_text.setText("正在生成 ROP Chain，请稍候...")
        thread = threading.Thread(target=self._ropchain_thread, args=(filepath,), daemon=True)
        thread.start()

    def run_string_search(self):
        filepath = self.path_input.text()
        search_str = self.string_search_input.text()
        
        if not self._validate_file(filepath):
            return
        
        if not search_str:
            QMessageBox.warning(self, "警告", "请输入要搜索的字符串。")
            return
            
        self.strings_text.setText(f"正在搜索字符串 '{search_str}'...")
        thread = threading.Thread(target=self._string_search_thread, args=(filepath, search_str), daemon=True)
        thread.start()

    def run_seccomp(self):
        filepath = self.path_input.text()
        if not self._validate_file(filepath):
            return
            
        self.seccomp_text.setText("正在分析 Seccomp 规则，请稍候...")
        thread = threading.Thread(target=self._seccomp_thread, args=(filepath,), daemon=True)
        thread.start()

    def run_one_gadget(self):
        libc_path = self.libc_path_input.text()
        if not self._validate_file(libc_path):
            return
            
        self.one_gadget_text.setText("正在查找 One Gadget，请稍候...")
        thread = threading.Thread(target=self._one_gadget_thread, args=(libc_path,), daemon=True)
        thread.start()

    def _validate_file(self, filepath):
        if not filepath:
            QMessageBox.warning(self, "警告", "请先选择一个文件。")
            return False
        
        if not os.path.exists(filepath):
            QMessageBox.critical(self, "错误", "文件不存在。")
            return False
        return True

    def _run_cmd(self, cmd):
        """辅助函数：运行命令行命令"""
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                encoding='utf-8', 
                errors='ignore',
                startupinfo=startupinfo
            )
            
            if result.returncode != 0:
                return f"Command failed (Code {result.returncode}):\n{result.stderr}\n{result.stdout}"
            
            return result.stdout
            
        except FileNotFoundError:
            return f"Error: Command not found: {cmd[0]}"
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def _run_ropgadget_cmd(self, args):
        """辅助函数：运行 ROPgadget 命令"""
        cmd = ["ROPgadget"] + args
        output = self._run_cmd(cmd)
        if "Command not found" in output:
             cmd = [sys.executable, "-m", "ROPgadget"] + args
             output = self._run_cmd(cmd)
        return output

    def _analyze_thread(self, filepath):
        self.update_status_signal.emit(f"正在分析 {os.path.basename(filepath)}...")
        
        # 1. Checksec & Symbols 分析
        try:
            if PWNTOOLS_AVAILABLE:
                try:
                    elf = ELF(filepath, checksec=False)
                except TypeError:
                    elf = ELF(filepath)
                
                # Checksec 结果
                results = {}
                results["架构"] = f"{elf.arch}-{elf.bits}-{elf.endian}"
                
                if hasattr(elf, 'relro'):
                    if elf.relro == 'Full':
                        results["RELRO"] = "Full RELRO"
                    elif elf.relro == 'Partial':
                        results["RELRO"] = "Partial RELRO"
                    else:
                        results["RELRO"] = "No RELRO"
                else:
                    results["RELRO"] = "Unknown"

                if hasattr(elf, 'canary'):
                    results["Stack"] = 'Canary found' if elf.canary else 'No canary found'
                else:
                    results["Stack"] = "Unknown"

                if hasattr(elf, 'nx'):
                    results["NX"] = 'NX enabled' if elf.nx else 'NX disabled'
                else:
                    results["NX"] = "Unknown"

                if hasattr(elf, 'pie'):
                    if elf.pie:
                        results["PIE"] = 'PIE enabled'
                    else:
                        results["PIE"] = f'No PIE (0x{elf.address:x})'
                else:
                    results["PIE"] = "Unknown"
                
                self.update_checksec_signal.emit(results)

                # 符号表与导入函数分析
                symbols_data = []
                
                # 导入函数 (高亮高危函数)
                dangerous_funcs = ['system', 'execve', 'gets', 'strcpy', 'strcat', 'sprintf']
                if hasattr(elf, 'symbols'):
                    for name, addr in sorted(elf.symbols.items()):
                        is_dangerous = False
                        if name in dangerous_funcs or "system" in name or "exec" in name:
                            is_dangerous = True
                        
                        # 如果是高危函数，优先添加到列表
                        item = {
                            'type': 'Symbol', 
                            'name': name, 
                            'addr': f"0x{addr:x}",
                            'dangerous': is_dangerous
                        }
                        
                        if is_dangerous:
                            symbols_data.insert(0, item)
                        else:
                            symbols_data.append(item)

                # GOT 表
                if hasattr(elf, 'got'):
                    for name, addr in elf.got.items():
                        symbols_data.append({'type': 'GOT', 'name': name, 'addr': f"0x{addr:x}"})

                # PLT 表
                if hasattr(elf, 'plt'):
                    for name, addr in elf.plt.items():
                        symbols_data.append({'type': 'PLT', 'name': name, 'addr': f"0x{addr:x}"})

                self.update_symbols_signal.emit(symbols_data)

            else:
                self.error_signal.emit("未检测到 pwntools，跳过 Checksec 分析")
            
        except Exception as e:
            self.error_signal.emit(f"Checksec 分析失败: {str(e)}")
            return

        # 2. ROPGadget 分析
        self.update_status_signal.emit("正在搜索 Gadgets (可能需要几秒钟)...")
        
        try:
            output = self._run_ropgadget_cmd(["--binary", filepath])
            gadgets = output.splitlines()
            self.update_gadgets_signal.emit(gadgets)
            self.update_status_signal.emit("分析完成")
            
        except Exception as e:
            self.error_signal.emit(f"ROPgadget 分析失败: {str(e)}\n请确保已安装 ROPgadget")

    def _ropchain_thread(self, filepath):
        try:
            output = self._run_ropgadget_cmd(["--binary", filepath, "--ropchain"])
            self.update_ropchain_signal.emit(output)
        except Exception as e:
            self.update_ropchain_signal.emit(f"生成 ROP Chain 失败: {str(e)}")

    def _string_search_thread(self, filepath, search_str):
        try:
            output = self._run_ropgadget_cmd(["--binary", filepath, "--string", search_str])
            self.update_string_search_signal.emit(output)
        except Exception as e:
            self.update_string_search_signal.emit(f"搜索字符串失败: {str(e)}")

    def _seccomp_thread(self, filepath):
        cmd = ["seccomp-tools", "dump", filepath]
        output = self._run_cmd(cmd)
        if "Command not found" in output:
             output += "\n\n提示: 请确保已安装 seccomp-tools (gem install seccomp-tools)"
        self.update_seccomp_signal.emit(output)

    def _one_gadget_thread(self, libc_path):
        cmd = ["one_gadget", libc_path]
        output = self._run_cmd(cmd)
        if "Command not found" in output:
             output += "\n\n提示: 请确保已安装 one_gadget (gem install one_gadget)"
        self.update_one_gadget_signal.emit(output)

    def update_status(self, msg):
        self.status_label.setText(msg)

    def update_checksec_ui(self, results):
        for key, value in results.items():
            if key in self.result_labels:
                self.result_labels[key].setText(value)
                
                # 简单的颜色标记
                if key == "NX" and "enabled" in value:
                    self.result_labels[key].setStyleSheet("color: #28a745; font-weight: bold;")
                elif key == "Stack" and "Canary" in value:
                    self.result_labels[key].setStyleSheet("color: #28a745; font-weight: bold;")
                elif key == "RELRO" and "Full" in value:
                    self.result_labels[key].setStyleSheet("color: #28a745; font-weight: bold;")
                elif key == "PIE" and "enabled" in value:
                    self.result_labels[key].setStyleSheet("color: #28a745; font-weight: bold;")

    def update_symbols_ui(self, symbols_data):
        self.symbols_table.setRowCount(len(symbols_data))
        
        for row, item in enumerate(symbols_data):
            type_item = QTableWidgetItem(item['type'])
            name_item = QTableWidgetItem(item['name'])
            addr_item = QTableWidgetItem(item['addr'])
            
            # 高危函数高亮
            if item.get('dangerous'):
                color = QColor("#ffebee") # 浅红色背景
                type_item.setBackground(color)
                name_item.setBackground(color)
                addr_item.setBackground(color)
                name_item.setForeground(QBrush(QColor("#d73a49"))) # 红色文字
                name_item.setFont(QFont("Consolas", 10, QFont.Bold))
            
            self.symbols_table.setItem(row, 0, type_item)
            self.symbols_table.setItem(row, 1, name_item)
            self.symbols_table.setItem(row, 2, addr_item)

    def update_gadgets_data(self, gadgets):
        self.gadgets_data = gadgets
        self.filter_gadgets()

    def update_ropchain_ui(self, text):
        self.ropchain_text.setPlainText(text)

    def update_string_search_ui(self, text):
        self.strings_text.setPlainText(text)

    def update_seccomp_ui(self, text):
        self.seccomp_text.setPlainText(text)

    def update_one_gadget_ui(self, text):
        self.one_gadget_text.setPlainText(text)

    def filter_gadgets(self):
        search_term = self.search_input.text().lower()
        
        # 清空表格
        self.gadget_table.setRowCount(0)
        
        filtered_items = []
        count = 0
        MAX_DISPLAY = 2000
        
        for line in self.gadgets_data:
            if search_term in line.lower():
                # 尝试解析地址和指令: 0x000000000040111d : pop rdi ; ret
                parts = line.split(' : ', 1)
                if len(parts) == 2:
                    addr, instr = parts[0].strip(), parts[1].strip()
                    filtered_items.append((addr, instr))
                else:
                    # 无法解析的行（可能是标题或空行），如果包含搜索词也显示
                    if line.strip():
                        filtered_items.append(("", line.strip()))
                
                count += 1
                if count >= MAX_DISPLAY:
                    break
        
        self.gadget_table.setRowCount(len(filtered_items))
        for row, (addr, instr) in enumerate(filtered_items):
            self.gadget_table.setItem(row, 0, QTableWidgetItem(addr))
            self.gadget_table.setItem(row, 1, QTableWidgetItem(instr))

    def show_error(self, msg):
        QMessageBox.critical(self, "错误", msg)
        self.status_label.setText("发生错误")

if __name__ == "__main__":
    # 检查是否安装了 PyQt5
    if 'PyQt5' not in sys.modules:
        try:
            import PyQt5
        except ImportError:
            print("请先安装 PyQt5: pip install PyQt5")
            sys.exit(1)

    app = QApplication(sys.argv)
    window = PwnCheckApp()
    window.show()
    sys.exit(app.exec_())
