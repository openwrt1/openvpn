#!/bin/bash
# 为 Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux, AlmaLinux 和 Alpine Linux 安装安全的 OpenVPN 服务器。
# https://github.com/yhdxtn/OpenVpn
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ 您的 Debian 版本不受支持。"
				echo ""
				echo "不过，如果您使用的是 Debian >= 9 或不稳定/测试版本，可以自行决定继续操作。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ 您的 Ubuntu 版本不受支持。"
				echo ""
				echo "不过，如果您使用的是 Ubuntu >= 16.04 或测试版，可以自行决定继续操作。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ 您的 CentOS 版本不受支持。"
				echo ""
				echo "此脚本仅支持 CentOS 7 和 CentOS 8。"
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "您的 Oracle Linux 版本不受支持。"
				echo ""
				echo "此脚本仅支持 Oracle Linux 8。"
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ 您的 Amazon Linux 版本不受支持。"
				echo ""
				echo "此脚本仅支持 Amazon Linux 2。"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
	else
		echo "看起来您不是在 Debian、Ubuntu、Fedora、CentOS、Amazon Linux 2、Oracle Linux 8、Arch Linux 或 Alpine Linux 系统上运行此安装程序。"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "抱歉，您需要以 root 身份运行此脚本"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN 不可用"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# 如果未安装 Unbound，则安装它
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# 配置
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# 配置
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# 配置
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# 获取根服务器列表
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		elif [[ $OS == "alpine" ]]; then
			apk add --update unbound
			# 配置
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf
		fi

		# 所有操作系统的 IPv6 DNS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS 反弹修复
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound 已安装
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# 为 OpenVPN 子网添加 Unbound 'server'
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	if [[ $OS == "alpine" ]]; then
		rc-update add unbound default
		rc-service unbound restart
	else
		systemctl enable unbound
		systemctl restart unbound
	fi
}

function installQuestions() {
	echo "欢迎使用 OpenVPN 安装程序！"
	echo "Git 仓库地址：https://github.com/angristan/openvpn-install"
	echo ""

	echo "在开始设置之前，我需要问你几个问题。"
	echo "你可以保留默认选项，并在确认时按回车键。"
	echo ""

	# 检测公共 IPv4 和 IPv6 地址
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z $IP ]]; then
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi

	echo "检查 IPv6 连接..."
	# "ping6" 和 "ping -6" 可用性因发行版而异
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "你的主机似乎有 IPv6 连接。"
		SUGGESTION="y"
	else
		echo "你的主机似乎没有 IPv6 连接。"
		SUGGESTION="n"
	fi
	
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "你想启用 IPv6 支持（NAT）吗？[y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done

	echo ""
	echo "你想为 VPN 使用哪种网络模式？"
	echo "   1) 仅 IPv4"
	echo "   2) 仅 IPv6"
	echo "   3) 双栈 (IPv4 和 IPv6)"
	until [[ $NETWORK_MODE =~ ^[1-3]$ ]]; do
		read -rp "网络模式 [1-3]: " -e -i 1 NETWORK_MODE
	done
	
	echo ""
	echo "我需要知道你希望 OpenVPN 监听的网络接口的 IP 地址。"
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP 地址: " -e -i "$IP" IP
	fi

	# 如果 $IP 是私有 IP 地址，服务器必须在 NAT 后面
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "看起来这台服务器在 NAT 后面。我们需要它的公共地址或主机名。"

		if [[ $NETWORK_MODE == "3" ]]; then
			PUBLIC_IP_V4=$(curl -s https://api.ipify.org)
			read -rp "公共 IPv4 地址或主机名: " -e -i "$PUBLIC_IP_V4" ENDPOINT_V4

			if ! [[ "$ENDPOINT_V4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "$ENDPOINT_V4" =~ .*:.* ]]; then
				ENDPOINT_V6=$ENDPOINT_V4
				echo "检测到主机名，将用于 IPv4 和 IPv6。"
			else
				PUBLIC_IP_V6=$(curl -s https://api64.ipify.org)
				read -rp "公共 IPv6 地址 (如果可用): " -e -i "$PUBLIC_IP_V6" ENDPOINT_V6
			fi
		elif [[ $NETWORK_MODE == "1" ]]; then
			PUBLICIP=$(curl -s https://api.ipify.org)
			until [[ $ENDPOINT != "" ]]; do
				read -rp "公共 IPv4 地址或主机名: " -e -i "$PUBLICIP" ENDPOINT
			done
		elif [[ $NETWORK_MODE == "2" ]]; then
			PUBLICIP=$(curl -s -6 https://api64.ipify.org)
			until [[ $ENDPOINT != "" ]]; do
				read -rp "公共 IPv6 地址或主机名: " -e -i "$PUBLICIP" ENDPOINT
			done
		fi
	fi

	# 如果是仅 IPv6 模式，自动检测公共 IPv6 地址
	if [[ $NETWORK_MODE == "2" && -z $ENDPOINT ]]; then
		echo ""
		echo "在仅 IPv6 模式下，正在自动检测公共 IPv6 地址..."
		# 优先使用外部 API 检测，因为它能反映真实的外部 IP。依次尝试多个 API。
		echo "尝试 API 1: api64.ipify.org"
		PUBLIC_IP_V6=$(curl -s -6 --connect-timeout 5 https://api64.ipify.org)

		if [[ -z $PUBLIC_IP_V6 ]]; then
			echo "API 1 失败。尝试 API 2: ip.sb"
			PUBLIC_IP_V6=$(curl -s -6 --connect-timeout 5 https://api.ip.sb)
		fi

		if [[ -z $PUBLIC_IP_V6 ]]; then
			echo "API 2 失败。尝试 API 3: ifconfig.co"
			PUBLIC_IP_V6=$(curl -s -6 --connect-timeout 5 https://ifconfig.co)
		fi

		if [[ -z $PUBLIC_IP_V6 ]]; then
			echo "所有外部 API 检测均失败，正在尝试从本地接口查找..."
			PUBLIC_IP_V6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		fi
		ENDPOINT=$PUBLIC_IP_V6
		echo "检测到公共 IPv6 地址: $ENDPOINT"
	fi

	echo ""
	echo "你希望 OpenVPN 监听哪个端口？"
	echo "   1) 默认：1194"
	echo "   2) 自定义"
	echo "   3) 随机 [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# 生成私有端口范围内的随机数
		PORT=$(shuf -i49152-65535 -n1)
		echo "随机端口: $PORT"
		;;
	esac
	echo ""
	echo "你希望 OpenVPN 使用哪种协议？"
	echo "UDP 更快。除非不可用，否则不应使用 TCP。"
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "你希望 VPN 使用哪些 DNS 解析器？"
	echo "   1) 当前系统解析器（来自 /etc/resolv.conf）"
	echo "   2) 自托管 DNS 解析器（Unbound）"
	echo "   3) Cloudflare (Anycast: 全球)"
	echo "   4) Quad9 (Anycast: 全球)"
	echo "   5) Quad9 未过滤版 (Anycast: 全球)"
	echo "   6) FDN (法国)"
	echo "   7) DNS.WATCH (德国)"
	echo "   8) OpenDNS (Anycast: 全球)"
	echo "   9) Google (Anycast: 全球)"
	echo "   10) Yandex Basic (俄罗斯)"
	echo "   11) AdGuard DNS (Anycast: 全球)"
	echo "   12) NextDNS (Anycast: 全球)"
	echo "   13) 自定义"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound 已安装。"
			echo "你可以允许脚本配置它，以便从 OpenVPN 客户端使用它。"
			echo "我们将简单地为 OpenVPN 子网添加第二个服务器到 /etc/unbound/unbound.conf。"
			echo "不会对当前配置进行任何更改。"
			echo ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "应用配置更改到 Unbound？[y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# 中断循环并清理
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "主 DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "次要 DNS（可选）: " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "你想启用压缩吗？由于 VORACLE 攻击，建议不启用。"
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"启用压缩？[y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "选择你要使用的压缩算法：（按效率排序）"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZO"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"压缩算法 [1-3]: " -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo" # 修复：将 'lz0' 改为正确的 'lzo'
			;;
		esac
	fi
	echo ""
	echo "你想自定义加密设置吗？"
	echo "除非你知道自己在做什么，否则你应该坚持使用脚本提供的默认参数。"
	echo "请注意，无论你选择什么，脚本中提供的所有选择都是安全的。（不像 OpenVPN 的默认设置）"
	echo "查看更多信息请访问：https://github.com/angristan/openvpn-install#security-and-encryption"
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# 使用默认、安全且快速的参数
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "选择你想用于数据通道的加密算法："
		echo "   1) AES-128-GCM（推荐）"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "选择你想用于证书的密钥类型："
		echo "   1) ECDSA（推荐）"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"证书密钥类型 [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "选择你想用于证书密钥的曲线："
			echo "   1) prime256v1（推荐）"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择你想用于证书密钥的 RSA 密钥大小："
			echo "   1) 2048 位（推荐）"
			echo "   2) 3072 位"
			echo "   3) 4096 位"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA 密钥大小 [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择你想用于控制通道的加密算法："
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256（推荐）"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256（推荐）"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择你想用于 Diffie-Hellman 密钥的类型："
		echo "   1) ECDH（推荐）"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH 密钥类型 [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "选择你想用于 ECDH 密钥的曲线："
			echo "   1) prime256v1（推荐）"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择你想用于 Diffie-Hellman 密钥的大小："
			echo "   1) 2048 位（推荐）"
			echo "   2) 3072 位"
			echo "   3) 4096 位"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH 密钥大小 [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# "auth" 选项在 AEAD 加密算法中表现不同
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "摘要算法用于验证数据通道数据包和控制通道中的 tls-auth 数据包。"
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "摘要算法用于验证控制通道中的 tls-auth 数据包。"
		fi

		echo "你希望使用哪种摘要算法进行 HMAC？"
		echo "   1) SHA-256（推荐）"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "你可以为控制通道添加额外的安全层，使用 tls-auth 和 tls-crypt"
		echo "tls-auth 认证数据包，而 tls-crypt 认证并加密数据包。"
		echo "   1) tls-crypt（推荐）"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "控制通道额外的安全机制 [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "好了，这就是我需要的所有信息。我们现在准备设置你的 OpenVPN 服务器了。"
	echo "安装完成后你可以生成客户端配置文件。"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "按任意键继续..."
	fi
}

function configureFirewall() {
	# 使用传统的 iptables 方法
	echo "将使用 iptables 配置规则。"
	# 在两个脚本中添加 iptables 规则
	mkdir -p /etc/iptables

	# 添加规则的脚本
	echo "#!/bin/sh" >/etc/iptables/add-openvpn-rules.sh
	if [[ $NETWORK_MODE == "1" || $NETWORK_MODE == "3" ]]; then # 仅 IPv4 或双栈
		echo "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
iptables -I FORWARD -i $NIC -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD -i tun0 -o $NIC -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi

	if [[ $NETWORK_MODE == "2" || $NETWORK_MODE == "3" ]]; then # 仅 IPv6 或双栈
		echo "ip6tables -t nat -A POSTROUTING -s fd42:4
