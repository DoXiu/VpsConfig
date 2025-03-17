#!/bin/bash
set -euo pipefail

# 颜色定义
GREEN='\e[32m'
RED='\e[31m'
YELLOW='\e[33m'
NC='\e[0m'

# 日志函数
log_success() { echo -e "${GREEN}[✓] $1${NC}"; }
log_error() { echo -e "${RED}[✗] 错误：$1${NC}" >&2; exit 1; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }

# 检查 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "请使用 sudo 执行该脚本！"
    fi
}

#----------- 修复点：调整函数定义语法 -----------#
# 输入验证函数
function validate_port {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
}

function validate_ip {
    local ip=$1
    # 修复点：转义正则表达式括号
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
}

function validate_hostname {
    local hostname=$1
    [[ "$hostname" =~ ^[a-zA-Z0-9-]{1,63}$ ]] || return 1
}

#----------------------- 主逻辑 -----------------------#
check_root

# 更新系统
log_success "更新系统源并升级..."
apt update && apt upgrade -y || log_error "系统更新失败"

# 安装软件包
log_success "安装软件包..."
apt install -y unzip curl wget sudo fail2ban rsyslog systemd-timesyncd ufw htop || log_error "软件安装失败"

# 修改 hostname
read -p "$(echo -e ${GREEN}是否修改 hostname? (y/N)${NC}) " modify_hostname
if [[ "$modify_hostname" =~ ^[Yy]$ ]]; then
    while true; do
        read -p "请输入新的 hostname: " new_hostname
        if validate_hostname "$new_hostname"; then
            hostnamectl set-hostname "$new_hostname" || log_error "修改 hostname 失败"
            if ! grep -q "$new_hostname" /etc/hosts; then
                sed -i "1s/^/127.0.0.1\t$new_hostname\n/" /etc/hosts
            fi
            break
        else
            log_warn "hostname 只能包含字母、数字和短横线，且长度不超过63字符"
        fi
    done
fi

# 修改 SSH 端口
log_success "修改 SSH 端口..."
while true; do
    read -p "请输入新的 SSH 端口（默认 22）: " ssh_port
    ssh_port=${ssh_port:-22}
    if validate_port "$ssh_port"; then
        break
    else
        log_warn "端口必须是 1-65535 之间的整数！"
    fi
done

# 备份 SSH 配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i -E "s/^#?(Port|X11Forwarding) .*/Port $ssh_port\nX11Forwarding no/" /etc/ssh/sshd_config
systemctl restart ssh || log_error "SSH 服务重启失败"

# 配置 fail2ban
log_success "配置 fail2ban..."
tee /etc/fail2ban/jail.local > /dev/null << EOF
[sshd]
ignoreip = 127.0.0.1/8
enabled = true
filter = sshd
port = $ssh_port
maxretry = 3
findtime = 300
bantime = -1
banaction = ufw
logpath = /var/log/auth.log
EOF

# 配置 UFW
log_success "配置防火墙..."
ufw allow "$ssh_port"
read -p "$(echo -e ${YELLOW}即将启用防火墙，请确认已放行必要端口！继续？(y/N)${NC}) " confirm
[[ "$confirm" =~ ^[Yy]$ ]] && ufw enable || log_warn "已跳过防火墙启用步骤"

# 修改 DNS
read -p "$(echo -e ${GREEN}是否修改 DNS 配置？(y/N)${NC}) " modify_dns
if [[ "$modify_dns" =~ ^[Yy]$ ]]; then
    while true; do
        read -p "请输入 DNS 服务器（多个用空格分隔）: " dns_servers
        all_valid=true
        for dns in $dns_servers; do
            validate_ip "$dns" || all_valid=false
        done
        
        if $all_valid; then
            # 处理 systemd-resolved 冲突
            if systemctl is-active --quiet systemd-resolved; then
                log_warn "检测到 systemd-resolved 正在运行，建议禁用后再修改 DNS"
                read -p "是否停止 systemd-resolved 服务？(y/N) " stop_resolved
                [[ "$stop_resolved" =~ ^[Yy]$ ]] && systemctl stop systemd-resolved
            fi
            
            cp /etc/resolv.conf /etc/resolv.conf.bak
            chattr -i /etc/resolv.conf 2>/dev/null
            printf "nameserver %s\n" $dns_servers > /etc/resolv.conf
            chattr +i /etc/resolv.conf
            break
        else
            log_warn "包含无效的 IP 地址，请重新输入！"
        fi
    done
fi

# 配置 Swap
read -p "$(echo -e ${GREEN}是否配置 Swap？(y/N)${NC}) " modify_swap
if [[ "$modify_swap" =~ ^[Yy]$ ]]; then
    while true; do
        read -p "Swap 大小 (MB，建议为内存的1-2倍): " SWAP_SIZE
        [[ "$SWAP_SIZE" =~ ^[0-9]+$ ]] && break || log_warn "请输入正整数"
    done

    while true; do
        read -p "Swappiness 值 (1-100，默认60): " SWAPPINESS
        SWAPPINESS=${SWAPPINESS:-60}
        [[ "$SWAPPINESS" =~ ^[0-9]+$ ]] && [ "$SWAPPINESS" -ge 1 ] && [ "$SWAPPINESS" -le 100 ] && break
        log_warn "请输入1-100之间的整数"
    done

    SWAP_FILE=${SWAP_FILE:-/swapfile}
    if [ -n "$(swapon --show=NAME --noheadings)" ]; then
        log_warn "检测到现有 Swap，将清除后重建！"
        swapoff -a
        sed -i '/swap/d' /etc/fstab
    fi

    log_success "创建 Swap 文件..."
    if ! fallocate -l "${SWAP_SIZE}M" "$SWAP_FILE"; then
        dd if=/dev/zero of="$SWAP_FILE" bs=1M count=$SWAP_SIZE status=progress || log_error "Swap 文件创建失败"
    fi
    
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" || log_error "mkswap 失败"
    swapon "$SWAP_FILE" || log_error "swapon 失败"
    echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    
    sysctl vm.swappiness=$SWAPPINESS
    echo "vm.swappiness=$SWAPPINESS" >> /etc/sysctl.conf
fi

# 服务管理
log_success "启动服务..."
systemctl restart fail2ban && systemctl enable fail2ban || log_warn "fail2ban 配置失败"
systemctl restart systemd-timesyncd && systemctl enable systemd-timesyncd

log_success "所有配置已完成！"
echo -e "\n${YELLOW}重要提示："
echo "1. 请确认可通过端口 $ssh_port 连接 SSH"
echo "2. 当前防火墙规则："
ufw status
echo -e "${NC}"
