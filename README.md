# VPS基础的配置一键脚本

*自动更新软件源并升级

*自动安装unzip curl wget sudo fail2ban rsyslog systemd-timesyncd ufw htop cron

*根据交互的方式修改hostname

*根据交互的方式修改ssh端口，并使用fail2ban对ssh进行保护，使用ufw放行该端口

*根据交互的方式修改dns，并对resolv.conf文件进行加锁，防止被重置

*通过交互的方式创建swap交换文件并启用

*BBR+fq 的tcp窗口调优

*ipv6 开启关闭

使用方法：

wget -N https://raw.githubusercontent.com/DoXiu/VpsConfig/refs/heads/main/VpsConfig.sh && chmod +x VpsConfig.sh && ./VpsConfig.sh

根据 nodeseke 帖子 https://www.nodeseek.com/post-290050-1 修改
