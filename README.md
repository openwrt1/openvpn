# OpenVPN-install

这个脚本可以让你在 Debian, Ubuntu, CentOS, Fedora, Arch Linux, Oracle Linux, Rocky Linux, AlmaLinux 和 Alpine Linux 上轻松地架设属于你自己的 OpenVPN 服务器。

该脚本基于 [angristan/openvpn-install](https://github.com/angristan/openvpn-install) 并进行了修改。

## `main` 分支 (推荐)

此分支提供稳定版本，安装时可选择“仅 IPv4”或“仅 IPv6”模式。
*   **仅 IPv4 模式**: 服务器将同时监听 IPv4 和 IPv6 地址，并能处理双栈流量，但客户端默认使用 IPv4 连接。
*   **仅 IPv6 模式**: 服务器仅监听 IPv6 地址。

### 安装 `main` 分支

```sh
wget https://raw.githubusercontent.com/openwrt1/openvpn/main/Openvpn.sh && chmod +x Openvpn.sh && ./Openvpn.sh
```

这个命令会下载、设为可执行，并运行安装脚本。之后，你只需要根据提示回答几个问题即可完成安装。
