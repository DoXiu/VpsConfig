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
log_warn() { printf "%b\n" "${YELLOW}[!] $1${NC}"; }

# 检查 root 权限 
check_root() {
    if [ "$(id -u)" -ne 0 ]; then 
        log_error "请使用 sudo 执行该脚本！"
    fi 
}

# 输入验证函数 
function validate_port {
    local port=$1 
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1 
}

function validate_ip {
    local ip=$1 
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1 
}

function validate_hostname {
    local hostname=$1 
    [[ "$hostname" =~ ^[a-zA-Z0-9-]{1,63}$ ]] || return 1 
}

#----------------------- 主逻辑 -----------------------#
check_root 

# 初始化配置跟踪变量 
CURRENT_HOSTNAME=$(hostname)
CURRENT_SSH_PORT=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
CURRENT_DNS=$(grep -E "^nameserver" /etc/resolv.conf    2>/dev/null | awk '{print $2}' | tr '\n' ' ')
CURRENT_SWAP=$(swapon --show=NAME,SIZE --noheadings | awk '{print $1 " (" $2 ")"}' | tr '\n' ',' | sed 's/,$//')
CURRENT_FAIL2BAN_MAXRETRIES="3"
CURRENT_FAIL2BAN_BANTIME="24"
CURRENT_FAIL2BAN_FINDTIME="3600"

# 更新系统 
log_success "更新系统源并升级..."
apt update && apt upgrade -y || log_error "系统更新失败"

# 安装软件包 
log_success "安装软件包..."
apt install -y unzip curl wget sudo fail2ban rsyslog systemd-timesyncd ufw htop cron || log_error "软件安装失败"

# ---------------------- 配置修改部分 ---------------------- #
# [1] 修改 hostname 
echo -e "\n${YELLOW}当前 hostname: $CURRENT_HOSTNAME${NC}"
read -p "$(printf "%b" "${GREEN}是否修改 hostname? (y/N)${NC} ")" modify_hostname 
if [[ "$modify_hostname" =~ ^[Yy]$ ]]; then 
    while true; do 
        read -p "请输入新的 hostname: " new_hostname 
        if validate_hostname "$new_hostname"; then 
            hostnamectl set-hostname "$new_hostname" || log_error "修改 hostname 失败"
            if ! grep -q "$new_hostname" /etc/hosts; then 
                sed -i "1s/^/127.0.0.1\t$new_hostname\n/" /etc/hosts 
            fi 
            CURRENT_HOSTNAME=$new_hostname 
            break 
        else 
            log_warn "hostname 只能包含字母、数字和短横线，且长度不超过63字符"
        fi 
    done 
fi 

# [2] 修改 SSH 端口
echo -e "\n${YELLOW}当前 SSH 端口: $CURRENT_SSH_PORT${NC}"
log_success "修改 SSH 端口..."
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

# 备份并修改 SSH 配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak  
# 精准处理 Port 配置
sed -i "/^Port/d" /etc/ssh/sshd_config # 删除所有 Port 行
sed -i "/^#Port/d" /etc/ssh/sshd_config # 删除所有注释的 Port 行
echo "Port $CURRENT_SSH_PORT" >> /etc/ssh/sshd_config # 写入新端口
systemctl restart ssh || log_error "SSH 服务重启失败"
# 配置 ufw
echo -e "${GREEN}配置 ufw...${NC}"
ufw allow "$ssh_port"

# [3] 配置 fail2ban 
read -p "$(printf "%b" "${GREEN}是否修改 fail2ban 配置？(y/N)${NC} ")" modify_fail2ban 
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
ignoreip = $ignore_ips
bantime = $((bantime * 3600)) # 将小时转换为秒
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
read -p "$(printf "%b" "${GREEN}是否修改 DNS 配置？(y/N)${NC} ")" modify_dns
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
            
            cp /etc/resolv.conf   /etc/resolv.conf.bak  
            chattr -i /etc/resolv.conf   2>/dev/null
            printf "nameserver %s\n" $dns_servers > /etc/resolv.conf  
            chattr +i /etc/resolv.conf  
            CURRENT_DNS=$dns_servers  # 更新跟踪变量
            break
        else
            log_warn "包含无效的 IP 地址，请重新输入！"
        fi
    done
fi

# [5] 配置 Swap
echo -e "\n${YELLOW}当前 Swap 配置: ${CURRENT_SWAP:-无}${NC}"
read -p "$(printf "%b" "${GREEN}是否配置 Swap？(y/N)${NC} ")" modify_swap
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
    echo "vm.swappiness=$SWAPPINESS"   >> /etc/sysctl.conf  
    CURRENT_SWAP="${SWAP_FILE} (${SWAP_SIZE}MB)"  # 更新跟踪变量
fi

# 启动服务并设置开机自启
log_success "启动并设置 fail2ban 和 systemd-timesyncd 开机自启..."
systemctl start fail2ban systemd-timesyncd
systemctl enable fail2ban systemd-timesyncd
# 启用 ufw
echo -e "${GREEN}启用 ufw...${NC}"
ufw enable

# ---------------------- 最终配置汇总 ---------------------- #
log_success "所有配置已完成！"
echo -e "${YELLOW}\n==================== 最终配置汇总 ====================${NC}"
echo -e "1. Hostname: ${GREEN}$CURRENT_HOSTNAME${NC}"
echo -e "2. SSH 端口: ${GREEN}$CURRENT_SSH_PORT${NC}"
echo -e "3. fail2ban 配置:"
echo -e "   - 最大错误次数: ${GREEN}$CURRENT_FAIL2BAN_MAXRETRIES${NC}"
echo -e "   - 封禁时间: ${GREEN}$CURRENT_FAIL2BAN_BANTIME 小时${NC}"
echo -e "   - 检测时间窗口: ${GREEN}$CURRENT_FAIL2BAN_FINDTIME 秒${NC}"
echo -e "5. DNS 服务器: ${GREEN}${CURRENT_DNS:-未修改}${NC}"
echo -e "6. Swap 配置: ${GREEN}${CURRENT_SWAP:-未修改}${NC}"
echo -e "${YELLOW}===================================================${NC}"
