#!/bin/bash
# radius.sh - OpenVPN脚本，用于处理OpenVPN连接的上/下线事件，对python脚本进行封装
# 参数说明：
#   $1 - 操作类型（auth, acct, stop）
#   $2 - 账号信息文件，由openvpn回调时传递临时文件路径（仅在auth操作时使用）

# 设置虚拟环境路径
VENV="/etc/openvpn/plugin/.venv"
# 检查虚拟环境是否存在
if [ ! -d "${VENV}" ]; then
    echo "Virtual environment not found at ${VENV}. Please create it first. Using 'python3 -m venv ${VENV}'"
    exit 1
fi

# 激活虚拟环境并执行Python脚本
source "${VENV}/bin/activate"

# 打印环境变量用于debug
python /etc/openvpn/plugin/auth-radius-py/main.py env

python /etc/openvpn/plugin/auth-radius-py/main.py $@

deactivate