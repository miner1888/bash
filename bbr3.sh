#!/bin/bash

# 检查并安装必要的依赖
REQUIRED_CMDS=("curl" "wget" "dpkg" "awk" "sed" "sysctl" "update-grub")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "\033[31m缺少依赖：$cmd，正在安装...\033[0m"
        apt-get update && apt-get install -y $cmd
    fi
done

# 检测系统架构
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" && "$ARCH" != "x86_64" ]]; then
    echo -e "\033[31m(￣\u25A1￣)哇！这个脚本只支持 ARM 和 x86_64 架构哦~ 您的系统架构是：$ARCH\033[0m"
    exit 1
fi

# 获取当前 BBR 状态
CURRENT_ALGO=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
CURRENT_QDISC=$(sysctl net.core.default_qdisc | awk '{print $3}')

# sysctl 配置文件路径
SYSCTL_CONF="/etc/sysctl.d/99-joeyblog.conf"

# 函数：清理 sysctl.d 中的旧配置
clean_sysctl_conf() {
    if [[ ! -f "$SYSCTL_CONF" ]]; then
        touch "$SYSCTL_CONF"
    fi
    sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
    sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_CONF"
}

# 函数：询问是否永久保存更改
ask_to_save() {
    echo -n -e "\033[36m(｡♥‿♥｡) 要将这些配置永久保存到 $SYSCTL_CONF 吗？(y/n): \033[0m"
    read -r SAVE
    if [[ "$SAVE" == "y" || "$SAVE" == "Y" ]]; then
        clean_sysctl_conf
        echo "net.core.default_qdisc=$QDISC" | tee -a "$SYSCTL_CONF" > /dev/null
        echo "net.ipv4.tcp_congestion_control=$ALGO" | tee -a "$SYSCTL_CONF" > /dev/null
        sysctl --system > /dev/null
        echo -e "\033[1;32m(☆^ー^☆) 更改已永久保存啦~\033[0m"
    else
        echo -e "\033[33m(⌒_⌒;) 好吧，没有永久保存呢~\033[0m"
    fi
}

# 函数：从 GitHub 获取最新版本并动态生成下载链接
get_download_links() {
    echo -e "\033[36m正在从 GitHub 获取最新版本信息...\033[0m"
    BASE_URL="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
    RELEASE_DATA=$(curl -s "$BASE_URL")

    # 根据系统架构选择版本
    if [[ "$ARCH" == "aarch64" ]]; then
        TAG_NAME=$(echo "$RELEASE_DATA" | grep "tag_name" | grep "arm64" | head -n 1 | awk -F '"' '{print $4}')
    elif [[ "$ARCH" == "x86_64" ]]; then
        TAG_NAME=$(echo "$RELEASE_DATA" | grep "tag_name" | grep "x86_64" | head -n 1 | awk -F '"' '{print $4}')
    fi

    if [[ -z "$TAG_NAME" ]]; then
        echo -e "\033[31m未找到适合当前架构的版本。\033[0m"
        exit 1
    fi

    echo -e "\033[36m找到的最新版本：$TAG_NAME\033[0m"
    
    # 获取所有文件的下载链接
    DOWNLOAD_URL="https://github.com/byJoey/Actions-bbr-v3/releases/download/$TAG_NAME"
    ASSET_URLS=$(curl -s "$BASE_URL" | grep "browser_download_url" | grep "$TAG_NAME" | awk -F '"' '{print $4}')

    for URL in $ASSET_URLS; do
        FILE=$(basename "$URL")
        echo -e "\033[36m正在下载文件：$URL\033[0m"
        wget "$URL" -P /tmp/
        if [[ $? -ne 0 ]]; then
            echo -e "\033[31m下载失败：$URL\033[0m"
            exit 1
        fi
    done
}

# 函数：安装下载的包
install_packages() {
    echo -e "\033[36m开始安装下载的包...\033[0m"
    dpkg -i /tmp/linux-*.deb
    update-grub
    echo -e "\033[36m安装完成，即将重启系统加载新内核。\033[0m"
    reboot
}

# 美化输出的分隔线
print_separator() {
    echo -e "\033[34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

# 欢迎信息
print_separator
echo -e "\033[1;35m(☆ω☆)✧*｡ 欢迎来到 BBR 管理脚本世界哒！ ✧*｡(☆ω☆)\033[0m"
print_separator
echo -e "\033[36m当前 TCP 拥塞控制算法：\033[0m\033[1;32m$CURRENT_ALGO\033[0m"
echo -e "\033[36m当前队列管理算法：\033[0m\033[1;32m$CURRENT_QDISC\033[0m"
print_separator

# 提示用户选择操作
echo -e "\033[1;33m╭( ･ㅂ･)و ✧ 你可以选择以下操作哦：\033[0m"
echo -e "\033[33m 1. 🛠️  安装或更新 BBR v3\033[0m"
echo -e "\033[33m 2. 🔍 检查是否为 BBR v3\033[0m"
echo -e "\033[33m 3. ⚡ 使用 BBR + FQ 加速\033[0m"
echo -e "\033[33m 4. ⚡ 使用 BBR + FQ_PIE 加速\033[0m"
echo -e "\033[33m 5. ⚡ 使用 BBR + CAKE 加速\033[0m"
echo -e "\033[33m 6. 🗑️  卸载\033[0m"
print_separator
echo -n -e "\033[36m请选择一个操作 (1-6) (｡･ω･｡): \033[0m"
read -r ACTION

case "$ACTION" in
    1)
        echo -e "\033[1;32m٩(｡•́‿•̀｡)۶ 您选择了安装或更新 BBR v3！\033[0m"
        apt remove --purge $(dpkg -l | grep "joeyblog" | awk '{print $2}') -y
        get_download_links
        install_packages
        ;;
    2)
        echo -e "\033[1;32m(｡･ω･｡) 检查是否为 BBR v3...\033[0m"

        if modinfo tcp_bbr &> /dev/null; then
            BBR_VERSION=$(modinfo tcp_bbr | awk '/^version:/ {print $2}')
            if [[ "$BBR_VERSION" == "3" ]]; then
                echo -e "\033[36m检测到 BBR 模块版本：\033[0m\033[1;32m$BBR_VERSION\033[0m"
            else
                echo -e "\033[33m(￣﹃￣) 检测到 BBR 模块，但版本是：$BBR_VERSION，不是 v3！\033[0m"
                exit 1
            fi
        fi

        CURRENT_ALGO=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
        if [[ "$CURRENT_ALGO" == "bbr" ]]; then
            echo -e "\033[36m当前 TCP 拥塞控制算法：\033[0m\033[1;32m$CURRENT_ALGO\033[0m"
        else
            echo -e "\033[31m(⊙﹏⊙) 当前算法不是 bbr，而是：$CURRENT_ALGO\033[0m"
            exit 1
        fi

        echo -e "\033[1;32mヽ(✿ﾟ▽ﾟ)ノ 检测完成，BBR v3 已正确安装并生效！\033[0m"
        ;;
    3)
        echo -e "\033[1;32m(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ 使用 BBR + FQ 加速！\033[0m"
        ALGO="bbr"
        QDISC="fq"
        ask_to_save
        ;;
    4)
        echo -e "\033[1;32m٩(•‿•)۶ 使用 BBR + FQ_PIE 加速！\033[0m"
        ALGO="bbr"
        QDISC="fq_pie"
        ask_to_save
        ;;
    5)
        echo -e "\033[1;32m(ﾉ≧∀≦)ﾉ 使用 BBR + CAKE 加速！\033[0m"
        ALGO="bbr"
        QDISC="cake"
        ask_to_save
        ;;
    6)
        echo -e "\033[1;32mヽ(・∀・)ノ 您选择了卸载 BBR 内核！\033[0m"
        apt remove --purge $(dpkg -l | grep "joeyblog" | awk '{print $2}') -y
        ;;
    *)
        echo -e "\033[31m(￣▽￣)ゞ 无效的选项，请输入 1-6 之间的数字哦~\033[0m"
        ;;
esac
