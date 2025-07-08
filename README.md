# ovpn-radius-py
radius integration with python scripts
# ovpn-radius-py | OpenVPN Radius Plugin (Python)

Python-based OpenVPN plugin with Radius Authentication and Accounting support using the [pyrad](https://github.com/pyradius/pyrad) library.

## How to Install

```bash
# Install prerequisites
apt install python3 python3-pip sqlite3

# Install Python dependencies
pip3 install pyrad

# Copy config and script
mkdir -p /etc/openvpn/plugin
cp config.json /etc/openvpn/plugin
cp main.py /etc/openvpn/plugin
chmod 755 /etc/openvpn/plugin/main.py

# Create database folder sqlite
mkdir -p /etc/openvpn/plugin/db
touch /etc/openvpn/plugin/db/ovpn-radius.db
chmod -R 777 /etc/openvpn/plugin/db

# Create log file
touch /var/log/openvpn/radius-plugin.log
chown nobody:nogroup /var/log/openvpn/radius-plugin.log
```


## OpenVPN 配置示例

```bash
auth-user-pass-verify "/etc/openvpn/plugin/main.py auth " via-file
client-connect "/etc/openvpn/plugin/main.py acct "
client-disconnect "/etc/openvpn/plugin/main.py stop "
script-security 2
```

## 说明
- 灵感参考go版本，https://github.com/rakasatria/ovpn-radius
- 认证、记账、环境变量打印等功能与 Go 版一致。
- 使用纯 Python 实现 RADIUS 协议，不再依赖 radclient 工具。
- 日志、数据库、配置文件路径与 Go 版兼容。
