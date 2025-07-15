# ovpn-radius-py | OpenVPN Radius Plugin (Python)

Python-based OpenVPN plugin with Radius Authentication and Accounting support using the [pyrad](https://github.com/pyradius/pyrad) library.

## How to Install

```bash
# Install prerequisites
apt install python3 python3-pip sqlite3

# Install Python dependencies
pip3 install pyrad

# Copy config and script
mkdir -p /etc/openvpn/plugin/auth-radius-py

cp config.json /etc/openvpn/plugin
cp main.py /etc/openvpn/plugin/auth-radius-py/
cp radius.sh /etc/openvpn/plugin/auth-radius-py/
cp -a dictionary /etc/openvpn/plugin/auth-radius-py/
chmod 755 /etc/openvpn/plugin/auth-radius-py/radius.sh

# Create database sqlite
touch /etc/openvpn/plugin/auth-radius-py/ovpn-radius.db
chmod 666 /etc/openvpn/plugin/auth-radius-py/ovpn-radius.db

# Create log file
mkdir -p /var/log/openvpn/
touch /var/log/openvpn/radius-plugin.log
chmod 666 /var/log/openvpn/radius-plugin.log
```


## OpenVPN 配置示例

```bash
auth-user-pass-verify "/etc/openvpn/plugin/auth-radius-py/radius.sh auth " via-file
client-connect "/etc/openvpn/plugin/auth-radius-py/radius.sh acct "
client-disconnect "/etc/openvpn/plugin/auth-radius-py/radius.sh stop "
script-security 2
```

## 说明

- 认证、记账、环境变量打印等功能与 Go 版一致。
- 使用纯 Python 实现 RADIUS 协议，不再依赖 radclient 工具。

