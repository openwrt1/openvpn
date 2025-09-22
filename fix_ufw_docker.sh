#!/bin/bash
#
# 这个脚本用于修复 UFW (Uncomplicated Firewall) 与 Docker 同时使用时可能出现的
# 网络转发问题，该问题会导致服务器无法访问外部网络。
#

echo "正在为 UFW 添加 Docker 相关的转发规则..."

# 检查并替换为您的实际公网网卡名称 (例如: eth0, ens3, enp0s3)
PUBLIC_INTERFACE="eth0"

# 允许所有来自或去往 Docker 默认网桥的流量
ufw route allow in on docker0
ufw route allow out on docker0

# 允许从公网网卡进入并转发到 Docker 网络的流量
ufw route allow in on "eth0" out on docker0

# 允许所有相关的、已建立的连接被转发
ufw route allow proto any from any to any state RELATED,ESTABLISHED

echo "规则添加完成。正在重新加载 UFW..."

ufw reload

echo "UFW 已重新加载。请现在测试您的网络连接 (例如: ping 8.8.8.8)。"