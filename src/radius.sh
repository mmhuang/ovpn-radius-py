#!/bin/bash
# radius.sh - OpenVPN脚本，用于处理OpenVPN连接的上/下线事件，对python脚本进行封装
# 参数说明：$1=操作类型(up/down), $2=隧道设备名(tun0), 其余为OpenVPN传递的参数

# 设置虚拟环境路径
VENV="/etc/openvpn/plugin/.venv"

# 获取OpenVPN传递的环境变量（关键步骤）
# export SCRIPT_TYPE="$1"
# export DEV="$2"
# shift 2  # 移除前两个参数，剩余参数存入$@
# export OPENVPN_PARAMS="$@"

# 打印所有的环境变量
# echo "OpenVPN Environment Variables:" >> /var/log/openvpn/radius-plugin.log
# env | sort >> /var/log/openvpn/radius-plugin.log

# 激活虚拟环境并执行Python脚本
source "${VENV}/bin/activate"
python /etc/openvpn/plugin/auth-radius-py/main.py env
python /etc/openvpn/plugin/auth-radius-py/main.py $@
deactivate