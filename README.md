# OpenVPN-install

这个脚本可以让你在 Debian, Ubuntu, CentOS, Fedora, Arch Linux, Oracle Linux, Rocky Linux, AlmaLinux 和 Alpine Linux 上轻松地架设属于你自己的 OpenVPN 服务器。

该脚本基于 [angristan/openvpn-install](https://github.com/angristan/openvpn-install) 并进行了修改。

## `ipv4+ipv6` 分支 (测试)

此分支提供了一个传统的双栈选项，允许在安装时明确选择“双栈 (IPv4 和 IPv6)”模式。

### 安装 `ipv4+ipv6` 分支

```sh
wget https://raw.githubusercontent.com/openwrt1/openvpn/ipv4+ipv6/Openvpn.sh && chmod +x Openvpn.sh && ./Openvpn.sh
```

这个命令会下载、设为可执行，并运行安装脚本。之后，你只需要根据提示回答几个问题即可完成安装。
