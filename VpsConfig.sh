#!/bin/bash 
set -euo pipefail 

# 颜色定义（兼容性写法）
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'

# 日志函数 
log_success() { printf "%b\n" "${GREEN}[✓] $1${NC}"; }
log_error() { printf "%b\n" "${RED}[✗] 错误：$1${NC}" >&2; exit 1; }
log_warn()    { printf "%b\n" "${YELLOW}[!] $1${NC}"; }

# 检查 root 权限 
check_root() {
    if [ "$(id -u)" -ne 0 ]; then 
        log_error "请使用 sudo 执行该脚本！"
    fi 
}

# 输入验证函数 
validate_port() {
    local port=$1 
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1 
}

validate_ip() {
    local ip=$1
    local IFS=.
    local -a octets=($ip)
    # 必须为四个部分
    [ ${#octets[@]} -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done
}

validate_hostname() {
    local hostname=$1
    # 支持 FQDN：各标签由字母、数字开头和结尾，中间可包含短横线，长度1-63字符
    if [[ "$hostname" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$ ]]; then
        return 0
    else
        return 1
    fi
}

# 重启 SSH 服务函数（兼容 ssh/sshd 服务名）
restart_ssh_service() {
    if systemctl list-units --type=service | grep -qE "(sshd|ssh)\.service"; then
        # 尝试先重启 sshd 服务，再重启 ssh 服务
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            return 0
        else
            log_error "SSH 服务重启失败"
        fi
    else
        log_error "无法找到 SSH 服务"
    fi
}

#----------------------- 主逻辑 -----------------------#
check_root 

# 初始化配置跟踪变量 
CURRENT_HOSTNAME=$(hostname)
CURRENT_SSH_PORT=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-22}  # 若提取失败，默认使用22
CURRENT_DNS=$(grep -E "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{printf "%s ", $2}' | sed 's/ $//')
CURRENT_SWAP=$(swapon --show=NAME,SIZE --noheadings | awk '{print $1 " (" $2 ")"}' | tr '\n' ',' | sed 's/,$//')
CURRENT_FAIL2BAN_MAXRETRIES="3"
CURRENT_FAIL2BAN_BANTIME="24"
CURRENT_FAIL2BAN_FINDTIME="3600"
CURRENT_BBR="未配置"
CURRENT_IPV6_STATUS="未修改"

# 更新系统 
log_success "更新系统源并升级..."
apt update && apt upgrade -y || log_error "系统更新失败"

# 安装软件包 
log_success "安装软件包..."
apt install -y unzip curl wget sudo fail2ban rsyslog systemd-timesyncd htop cron || log_error "软件安装失败"

# ---------------------- 配置修改部分 ---------------------- #
# [1] 修改 hostname 
echo -e "\n${YELLOW}当前 hostname: $CURRENT_HOSTNAME${NC}"
read -p "$(printf "%b" "${GREEN}是否修改 hostname? (y/n) 默认 n: ${NC}")" modify_hostname 
if [[ "$modify_hostname" =~ ^[Yy]$ ]]; then 
    while true; do 
        read -p "请输入新的 hostname: " new_hostname 
        if validate_hostname "$new_hostname"; then
            # 修改系统 hostname
            hostnamectl set-hostname "$new_hostname" || log_error "修改 hostname 失败"
            # 更新 /etc/hosts：如果包含旧 hostname则替换，否则追加新行
            if grep -qE "127\.[0-9]+\.[0-9]+\.[0-9]+\s+.*\b$CURRENT_HOSTNAME\b" /etc/hosts; then
                sed -i "s/\b$CURRENT_HOSTNAME\b/$new_hostname/g" /etc/hosts
            elif ! grep -qE "127\.[0-9]+\.[0-9]+\.[0-9]+\s+.*\b$new_hostname\b" /etc/hosts; then
                echo -e "127.0.0.1\t$new_hostname" >> /etc/hosts
            fi 
            CURRENT_HOSTNAME=$new_hostname 
            break 
        else 
            log_warn "hostname 格式不正确，请输入合法的 FQDN 或单个标签（字母、数字和短横线，且不能以短横线开始或结束）"
        fi 
    done 
fi 

# [2] 修改 SSH 端口
echo -e "\n${YELLOW}当前 SSH 端口: $CURRENT_SSH_PORT${NC}"
old_ssh_port=$CURRENT_SSH_PORT
while true; do
    read -p "$(printf "%b" "${GREEN}请输入新的 SSH 端口（默认 $CURRENT_SSH_PORT）: ${NC}")" ssh_port
    ssh_port=${ssh_port:-$CURRENT_SSH_PORT}
    if validate_port "$ssh_port"; then
        CURRENT_SSH_PORT=$ssh_port
        break
    else
        log_warn "端口必须是 1-65535 之间的整数！"
    fi
done

# 备份并修改 SSH 配置（优化：注释掉所有已有的 Port 配置，追加新的 Port 指令）
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i '/^[[:space:]]*Port[[:space:]]\+[0-9]\+/ s/^/# /' /etc/ssh/sshd_config
echo "Port $CURRENT_SSH_PORT" >> /etc/ssh/sshd_config
restart_ssh_service

# [3] 配置 fail2ban 
read -p "$(printf "%b" "${GREEN}是否修改 fail2ban 配置？(y/n) 默认 n: ${NC}")" modify_fail2ban 
if [[ "$modify_fail2ban" =~ ^[Yy]$ ]]; then 
    # 修改最大错误次数 
    while true; do 
        read -p "最大允许错误次数（默认 $CURRENT_FAIL2BAN_MAXRETRIES）: " maxretry 
        maxretry=${maxretry:-$CURRENT_FAIL2BAN_MAXRETRIES}
        [[ "$maxretry" =~ ^[0-9]+$ ]] && break || log_warn "请输入正整数"
    done 

    # 修改封禁时间 
    while true; do 
        read -p "封禁时间（小时，默认 $CURRENT_FAIL2BAN_BANTIME）: " bantime 
        bantime=${bantime:-$CURRENT_FAIL2BAN_BANTIME}
        [[ "$bantime" =~ ^[0-9]+$ ]] && break || log_warn "请输入正整数"
    done 
    # 将小时转换为秒
    bantime_seconds=$((bantime * 3600))

    # 修改检测时间窗口 
    while true; do 
        read -p "检测时间窗口（秒，默认 $CURRENT_FAIL2BAN_FINDTIME）: " findtime 
        findtime=${findtime:-$CURRENT_FAIL2BAN_FINDTIME}
        [[ "$findtime" =~ ^[0-9]+$ ]] && break || log_warn "请输入正整数"
    done 

    # 创建配置文件 
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = $bantime_seconds
maxretry = $maxretry
findtime = $findtime
banaction = iptables-multiport
backend = systemd
[sshd]
enabled = true
port = $CURRENT_SSH_PORT # 使用脚本中已配置的SSH端口
filter = sshd
logpath = /var/log/auth.log 
EOF

    # 更新跟踪变量 
    CURRENT_FAIL2BAN_MAXRETRIES=$maxretry 
    CURRENT_FAIL2BAN_BANTIME=$bantime
    CURRENT_FAIL2BAN_FINDTIME=$findtime 
fi 

# [4] 配置 DNS
echo -e "\n${YELLOW}当前 DNS 服务器: ${CURRENT_DNS:-无配置}${NC}"
read -p "$(printf "%b" "${GREEN}是否修改 DNS 配置？(y/n) 默认 n: ${NC}")" modify_dns
if [[ "$modify_dns" =~ ^[Yy]$ ]]; then
    while true; do
        read -p "请输入 DNS 服务器（多个用空格分隔）: " dns_servers
        all_valid=true
        for dns in $dns_servers; do
            validate_ip "$dns" || all_valid=false
        done
        
        if $all_valid; then
            if systemctl is-active --quiet systemd-resolved; then
                log_warn "检测到 systemd-resolved 正在运行，建议禁用后再修改 DNS"
                read -p "$(printf "%b" "${YELLOW}是否停止 systemd-resolved 服务？(y/N) ${NC}")" stop_resolved
                [[ "$stop_resolved" =~ ^[Yy]$ ]] && systemctl stop systemd-resolved
            fi
            
            cp /etc/resolv.conf /etc/resolv.conf.bak  
            # 如果 /etc/resolv.conf 不是符号链接，则尝试修改属性
            if [ ! -L /etc/resolv.conf ]; then
                chattr -i /etc/resolv.conf 2>/dev/null || log_warn "无法取消 /etc/resolv.conf 的不可变属性"
            fi
            printf "nameserver %s\n" $dns_servers > /etc/resolv.conf  
            if [ ! -L /etc/resolv.conf ]; then
                chattr +i /etc/resolv.conf 2>/dev/null || log_warn "无法设置 /etc/resolv.conf 为不可变"
            fi
            CURRENT_DNS=$dns_servers  # 更新跟踪变量
            break
        else
            log_warn "包含无效的 IP 地址，请重新输入！"
        fi
    done
fi

# [5] 配置 Swap
echo -e "\n${YELLOW}当前 Swap 配置: ${CURRENT_SWAP:-无}${NC}"
read -p "$(printf "%b" "${GREEN}是否配置 Swap？(y/n) 默认 n: ${NC}")" modify_swap
if [[ "$modify_swap" =~ ^[Yy]$ ]]; then
    while true; do
        read -p "Swap 大小 (MB，建议为内存的1-2倍): " SWAP_SIZE
        [[ "$SWAP_SIZE" =~ ^[0-9]+$ ]] && break || log_warn "请输入正整数"
    done

    SWAP_FILE=${SWAP_FILE:-/swapfile}
    # 检查现有 Swap
    if swapon --show=NAME --noheadings | grep -q .; then
        log_warn "检测到现有 Swap，将清除后重建！"
        swapoff -a || log_warn "Swap 关闭失败"
        sed -i '/\s*'"$SWAP_FILE"'\s*/d' /etc/fstab
        if [ -f "$SWAP_FILE" ]; then
            rm -f "$SWAP_FILE"
        fi
    fi

    log_success "创建 Swap 文件..."
    if fallocate -l "${SWAP_SIZE}M" "$SWAP_FILE"; then
       log_success "Swap 文件创建成功 (fallocate)"
    else
       log_warn "fallocate 失败，改用 dd 创建..."
       dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$SWAP_SIZE status=progress || log_error "Swap 文件创建失败"
    fi
    
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" || log_error "mkswap 失败"
    swapon "$SWAP_FILE" || log_error "swapon 失败"
    echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    
    CURRENT_SWAP="${SWAP_FILE} (${SWAP_SIZE}MB)"  # 更新跟踪变量
fi

# [6] 配置 BBR 和 TCP 调优
echo -e "\n${YELLOW}当前 TCP 拥塞控制算法：$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)${NC}"
read -p "$(printf "%b" "${GREEN}是否配置 BBR 和 TCP 窗口调优？(y/n) 默认 n: ${NC}")" enable_bbr
if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
    # 输入带宽和延迟
    while true; do
        read -p "请输入服务器带宽（Mbps）：" bandwidth
        [[ "$bandwidth" =~ ^[0-9]+$ ]] && [ "$bandwidth" -gt 0 ] && break || log_warn "带宽必须为正整数"
    done
    while true; do
        read -p "请输入网络平均延迟（ms）：" latency
        [[ "$latency" =~ ^[0-9]+$ ]] && [ "$latency" -gt 0 ] && break || log_warn "延迟必须为正整数"
    done
    read -p "是否关闭 IPv6？（y/n）默认 n: " disable_ipv6

    # 计算带宽延迟积（单位：字节）公式：带宽(Mbps)*延迟(ms)*187（bash 算术扩展只支持整数运算，如需精确请用 bc/awk）
    bdp=$(( bandwidth * latency * 187 ))
    
    # 备份 sysctl 配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    # 生成调优配置
    cat > /etc/sysctl.conf << EOF

# --------------------- BBR & TCP 调优配置 --------------------- #
# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ECN 支持
net.ipv4.tcp_ecn = 0

# 文件描述符限制
fs.file-max = 1000000

# TCP 缓冲区优化（基于带宽延迟积）
net.core.rmem_max = $bdp
net.core.wmem_max = $bdp
net.ipv4.tcp_wmem = 4096 16384 $bdp
net.ipv4.tcp_rmem = 4096 87380 $bdp

# 连接优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_frto = 2
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1

# 端口范围调整
net.ipv4.ip_local_port_range = 1024 65535

# 性能优化
net.ipv4.tcp_syncookies = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.icmp_ratelimit = 1000
net.ipv4.icmp_ratemask = 8800
net.ipv4.tcp_low_latency = 1

# 网络转发
net.ipv4.conf.all.route_localnet = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
EOF

    # 关闭 IPv6
    if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
        cat >> /etc/sysctl.conf << EOF

# 禁用 IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        
        CURRENT_IPV6_STATUS="已禁用"
    else
        CURRENT_IPV6_STATUS="已启用"
    fi

    # 应用配置
    sysctl -p
    CURRENT_BBR="已启用 (BBR + FQ)"
fi
  
# 启动服务并设置开机自启
log_success "启动并设置 fail2ban 和 systemd-timesyncd 开机自启..."
systemctl start fail2ban systemd-timesyncd
systemctl enable fail2ban systemd-timesyncd

# ---------------------- 最终配置汇总 ---------------------- #
log_success "所有配置已完成！"
echo -e "${YELLOW}\n==================== 最终配置汇总 ====================${NC}"
echo -e "1. Hostname: ${GREEN}$CURRENT_HOSTNAME${NC}"
echo -e "2. SSH 端口: ${GREEN}$CURRENT_SSH_PORT${NC} 如果有防火墙请注意放行对应端口"
echo -e "3. fail2ban 配置:"
echo -e "   - 最大错误次数: ${GREEN}$CURRENT_FAIL2BAN_MAXRETRIES${NC}"
echo -e "   - 封禁时间: ${GREEN}$CURRENT_FAIL2BAN_BANTIME 小时${NC}"
echo -e "   - 检测时间窗口: ${GREEN}$CURRENT_FAIL2BAN_FINDTIME 秒${NC}"
echo -e "4. DNS 服务器: ${GREEN}${CURRENT_DNS:-未修改}${NC}"
echo -e "5. Swap 配置: ${GREEN}${CURRENT_SWAP:-未修改}${NC}"
echo -e "6. BBR 配置：${GREEN}${CURRENT_BBR:-未修改}${NC}"
echo -e "7. IPv6 状态：${GREEN}${CURRENT_IPV6_STATUS}${NC}"
echo -e "${YELLOW}===================================================${NC}"
