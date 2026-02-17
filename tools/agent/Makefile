# WD-Agent Makefile
# 静态编译多架构探针

CC ?= gcc
STRIP ?= strip
CFLAGS = -O2 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -static

AGENTS_DIR = ../../agents
TARGETS = $(AGENTS_DIR)/wd_agent_x64 $(AGENTS_DIR)/wd_agent_x86

.PHONY: all clean x64 x86 arm64 mips upload test

all: x64

x64: $(AGENTS_DIR)/wd_agent_x64

$(AGENTS_DIR)/wd_agent_x64: wd_agent.c | $(AGENTS_DIR)
	@echo "[+] Building x86_64..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) $@
	@echo "[+] Built: $@"
	@ls -lh $@

x86: $(AGENTS_DIR)/wd_agent_x86

$(AGENTS_DIR)/wd_agent_x86: wd_agent.c | $(AGENTS_DIR)
	@echo "[+] Building x86..."
	@which i686-linux-gnu-gcc >/dev/null 2>&1 && \
		i686-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -o $@ $< || \
		$(CC) -m32 $(CFLAGS) $(LDFLAGS) -o $@ $< 2>/dev/null || \
		echo "[!] x86 build failed, install gcc-multilib"
	@ls -lh $@ 2>/dev/null || true

arm64: $(AGENTS_DIR)/wd_agent_arm64

$(AGENTS_DIR)/wd_agent_arm64: wd_agent.c | $(AGENTS_DIR)
	@echo "[+] Building ARM64..."
	@which aarch64-linux-gnu-gcc >/dev/null 2>&1 && \
		aarch64-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -o $@ $< || \
		echo "[!] ARM64 build failed, install gcc-aarch64-linux-gnu"
	@ls -lh $@ 2>/dev/null || true

mips: $(AGENTS_DIR)/wd_agent_mips

$(AGENTS_DIR)/wd_agent_mips: wd_agent.c | $(AGENTS_DIR)
	@echo "[+] Building MIPS..."
	@which mips-linux-gnu-gcc >/dev/null 2>&1 && \
		mips-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -o $@ $< || \
		echo "[!] MIPS build failed, install gcc-mips-linux-gnu"
	@ls -lh $@ 2>/dev/null || true

$(AGENTS_DIR):
	mkdir -p $(AGENTS_DIR)

clean:
	rm -f $(AGENTS_DIR)/wd_agent_*

# 本地测试（需要root权限用于inotify）
test: x64
	@echo "[*] Testing agent (local mode)..."
	@echo "    Run: sudo $(AGENTS_DIR)/wd_agent_x64 127.0.0.1 8024 /tmp/wd_test -v"
	@mkdir -p /tmp/wd_test

upload: x64
	@echo "[*] Agents ready for upload:"
	@ls -lh $(AGENTS_DIR)/wd_agent_* 2>/dev/null || echo "    No agents built yet"
