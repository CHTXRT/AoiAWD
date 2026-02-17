/*
 * WD-Agent - AWD-Defender 轻量级文件监控探针
 * 编译: gcc -O2 -s -static -o wd_agent wd_agent.c
 * 运行: ./wd_agent <server_ip> [port] [watch_dir] [-d]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netdb.h>  // for getaddrinfo

#define BUFFER_SIZE 8192
#define MAX_PATH 4096
#define MAX_EVENTS 200
#define HEARTBEAT_SEC 30
#define MAX_WATCHES 1024

static char g_server_ip[64] = "127.0.0.1";  // 支持主机名如 host.docker.internal
static int g_server_port = 8024;
static char g_watch_dir[MAX_PATH] = "/var/www/html";
static volatile int g_running = 1;
static int g_daemon_mode = 0;
static int g_verbose = 0;

/* wd -> 目录路径映射表 */
static char *g_wd_to_path[MAX_WATCHES] = {NULL};

/* 批量事件缓冲 */
typedef struct {
    char path[MAX_PATH];
    unsigned int mask;
    time_t time;
} Event;

static Event g_batch[MAX_EVENTS];
static int g_batch_count = 0;
static time_t g_last_flush = 0;
static time_t g_last_heartbeat = 0;

static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        g_running = 0;
    }
}

/* JSON字符串转义 */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        unsigned char c = src[i];
        if (c == '"' || c == '\\' || c == '\b' || c == '\f' || 
            c == '\n' || c == '\r' || c == '\t') {
            if (j < dst_size - 3) {
                dst[j++] = '\\';
                switch(c) {
                    case '"': dst[j++] = '"'; break;
                    case '\\': dst[j++] = '\\'; break;
                    case '\b': dst[j++] = 'b'; break;
                    case '\f': dst[j++] = 'f'; break;
                    case '\n': dst[j++] = 'n'; break;
                    case '\r': dst[j++] = 'r'; break;
                    case '\t': dst[j++] = 't'; break;
                }
            }
        } else if (c < 0x20) {
            if (j < dst_size - 7) {
                j += sprintf(dst + j, "\\u%04x", c);
            }
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

/* 发送数据到服务器（支持主机名和IP） */
static int send_data(const char *data) {
    struct addrinfo hints, *res, *rp;
    int sock = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_server_port);
    
    // 解析主机名或IP
    if (getaddrinfo(g_server_ip, port_str, &hints, &res) != 0) {
        if (g_verbose) printf("[Error] Cannot resolve %s\n", g_server_ip);
        return -1;
    }
    
    // 尝试连接
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        
        struct timeval tv = {3, 0};  // 3秒超时
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // 连接成功
        }
        close(sock);
        sock = -1;
    }
    
    freeaddrinfo(res);
    
    if (sock < 0) {
        if (g_verbose) printf("[Error] Cannot connect to %s:%d\n", g_server_ip, g_server_port);
        return -1;
    }
    
    int len = strlen(data);
    int sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            close(sock);
            return -1;
        }
        sent += n;
    }
    
    close(sock);
    return 0;
}

/* 刷新批量缓冲 */
static void flush_batch(void) {
    if (g_batch_count == 0) return;
    
    char json[BUFFER_SIZE * 4];
    int pos = snprintf(json, sizeof(json), "{\"type\":\"batch\",\"events\":[", g_batch_count);
    
    char escaped[MAX_PATH * 2];
    for (int i = 0; i < g_batch_count && pos < (int)sizeof(json) - 256; i++) {
        json_escape(g_batch[i].path, escaped, sizeof(escaped));
        pos += snprintf(json + pos, sizeof(json) - pos,
            "%s{\"path\":\"%s\",\"mask\":%u,\"time\":%ld}",
            i > 0 ? "," : "", escaped, g_batch[i].mask, (long)g_batch[i].time);
    }
    
    pos += snprintf(json + pos, sizeof(json) - pos, "]}\n");
    
    if (g_verbose) printf("[Send] %d events\n", g_batch_count);
    send_data(json);
    
    g_batch_count = 0;
    g_last_flush = time(NULL);
}

/* 添加事件到缓冲 */
static void buffer_event(const char *path, unsigned int mask) {
    // 去重：相同路径合并mask
    for (int i = 0; i < g_batch_count; i++) {
        if (strcmp(g_batch[i].path, path) == 0) {
            g_batch[i].mask |= mask;
            g_batch[i].time = time(NULL);
            return;
        }
    }
    
    if (g_batch_count < MAX_EVENTS) {
        strncpy(g_batch[g_batch_count].path, path, MAX_PATH - 1);
        g_batch[g_batch_count].path[MAX_PATH - 1] = '\0';
        g_batch[g_batch_count].mask = mask;
        g_batch[g_batch_count].time = time(NULL);
        g_batch_count++;
    }
    
    // 满或超时则刷新
    time_t now = time(NULL);
    if (g_batch_count >= MAX_EVENTS || now - g_last_flush >= 1) {
        flush_batch();
    }
}

/* 发送心跳 */
static void send_heartbeat(void) {
    char json[256];
    snprintf(json, sizeof(json), 
        "{\"type\":\"heartbeat\",\"time\":%ld,\"dir\":\"%s\"}\n",
        (long)time(NULL), g_watch_dir);
    send_data(json);
    g_last_heartbeat = time(NULL);
}

/* 检查是否为PHP文件 */
static int is_php_file(const char *name) {
    size_t len = strlen(name);
    return (len > 4 && strcasecmp(name + len - 4, ".php") == 0);
}

/* 递归添加inotify watch */
static void add_watch_recursive(int fd, const char *base_path, int depth) {
    if (depth > 5) return;  // 限制递归深度
    
    int wd = inotify_add_watch(fd, base_path, 
        IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE);
    
    if (wd < 0) {
        if (g_verbose) printf("[Warn] Cannot watch %s: %s\n", base_path, strerror(errno));
        return;
    }
    
    /* 保存 wd -> path 映射 */
    if (wd >= 0 && wd < MAX_WATCHES) {
        if (g_wd_to_path[wd]) free(g_wd_to_path[wd]);
        g_wd_to_path[wd] = strdup(base_path);
    }
    
    if (g_verbose) printf("[Watch] wd=%d %s\n", wd, base_path);
    
    DIR *dir = opendir(base_path);
    if (!dir) return;
    
    struct dirent *entry;
    char full_path[MAX_PATH];
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (entry->d_name[0] == '.') continue;  // 跳过隐藏目录
        
        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);
        
        // 检查是否为符号链接，防止循环
        struct stat st;
        if (lstat(full_path, &st) == 0 && S_ISLNK(st.st_mode)) continue;
        
        add_watch_recursive(fd, full_path, depth + 1);
    }
    closedir(dir);
}

/* 处理新创建的目录 */
static void handle_new_dir(int fd, const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        add_watch_recursive(fd, path, 0);
    }
}

int main(int argc, char *argv[]) {
    /* 参数解析 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            g_daemon_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = 1;
        } else if (i == 1) {
            strncpy(g_server_ip, argv[i], sizeof(g_server_ip) - 1);
            g_server_ip[sizeof(g_server_ip) - 1] = '\0';
        } else if (i == 2) {
            g_server_port = atoi(argv[i]);
        } else if (i == 3) {
            strncpy(g_watch_dir, argv[i], MAX_PATH - 1);
            g_watch_dir[MAX_PATH - 1] = '\0';
        }
    }
    
    /* 守护模式 */
    if (g_daemon_mode) {
        if (daemon(0, g_verbose) < 0) {
            perror("daemon");
            return 1;
        }
    }
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    /* 初始化inotify */
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init");
        return 1;
    }
    
    add_watch_recursive(fd, g_watch_dir, 0);
    
    char buf[BUFFER_SIZE];
    g_last_flush = time(NULL);
    g_last_heartbeat = time(NULL);
    
    if (!g_daemon_mode || g_verbose) {
        printf("[WD-Agent] Watch: %s -> %s:%d (PID: %d)\n",
               g_watch_dir, g_server_ip, g_server_port, getpid());
    }
    
    /* 主循环 */
    while (g_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        
        struct timeval tv = {1, 0};  // 1秒超时
        int ret = select(fd + 1, &fds, NULL, NULL, &tv);
        time_t now = time(NULL);
        
        if (ret > 0 && FD_ISSET(fd, &fds)) {
            int len = read(fd, buf, sizeof(buf));
            if (len > 0) {
                int i = 0;
                while (i < len) {
                    struct inotify_event *e = (struct inotify_event*)&buf[i];
                    
                    if (e->len > 0) {
                        /* 构造完整路径：使用 wd 查找对应的目录 */
                        char full_path[MAX_PATH];
                        const char *dir_path = g_watch_dir;
                        
                        if (e->wd >= 0 && e->wd < MAX_WATCHES && g_wd_to_path[e->wd]) {
                            dir_path = g_wd_to_path[e->wd];
                        }
                        
                        snprintf(full_path, sizeof(full_path), "%s/%s", 
                                dir_path, e->name);
                        
                        // 检查是否是新目录
                        int is_dir = (e->mask & IN_ISDIR);
                        if (is_dir && (e->mask & IN_CREATE)) {
                            handle_new_dir(fd, full_path);
                        }
                        
                        // 只推送PHP文件，不推送目录（如2.php这种文件夹不推送）
                        if (!is_dir && is_php_file(e->name)) {
                            if (g_verbose) {
                                printf("[Event] %s mask=%u\n", full_path, e->mask);
                            }
                            buffer_event(full_path, e->mask);
                        }
                    }
                    i += sizeof(struct inotify_event) + e->len;
                }
            }
        }
        
        /* 定时刷新 */
        if (now - g_last_flush >= 1) {
            flush_batch();
        }
        
        /* 定时心跳 */
        if (now - g_last_heartbeat >= HEARTBEAT_SEC) {
            send_heartbeat();
        }
    }
    
    /* 清理 */
    flush_batch();
    close(fd);
    
    if (!g_daemon_mode || g_verbose) {
        printf("[WD-Agent] Exiting\n");
    }
    
    return 0;
}
