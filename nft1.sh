#!/bin/bash

# 颜色定义
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[95m'
NC='\e[0m'

# NFT 状态检测
check_nft() {
    if ! command -v nft &> /dev/null; then
        echo -e "${RED}nft 未安装${NC}"
        return 1
    fi

    if ! systemctl is-active --quiet nftables.service; then
        echo -e "${GREEN}已安装${NC} ${RED}● 未运行${NC}"
        return 2
    else
        echo -e "${GREEN}已安装 ● 正在运行${NC}"
        return 0
    fi
}

show_nft_status() {
    sleep 0.2
    nft_status=$(check_nft)
    echo -e "\n${YELLOW}nft 状态 →${NC} $nft_status"
}

# 启用 IP 转发（仅支持 IPv4）
enable_ip_forward() {
    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        echo -e "${GREEN}已开启 IPv4 转发功能${NC}"
    else
        echo -e "${GREEN}IPv4 转发功能已开启${NC}"
    fi
}

# 安装 NFT
install_nft() {
    apt-get update -y && apt-get install -y nftables
    enable_ip_forward
    systemctl enable nftables.service > /dev/null
    systemctl start nftables.service > /dev/null
    echo -e "${GREEN}nft 安装完成${NC}"
}

# 检查 SNAT 规则是否存在（仅 IPv4）
check_snat_exists() {
    local dest_addr=$1
    nft list table ip nat 2>/dev/null | grep -q "ip daddr $dest_addr masquerade" && return 0
    return 1
}

# 验证 IP 地址（仅支持 IPv4）
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -lt 0 ] || [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# 添加 NAT 规则（仅支持 IPv4）
add_nat_rule() {
    echo -e "${GREEN}选择协议：${NC}"
    echo -e "${GREEN}1. TCP${NC}"
    echo -e "${GREEN}2. UDP${NC}"
    echo -e "${GREEN}3. TCP/UDP${NC}"
    read -p "请选择: " protocol
    case $protocol in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        3) protocol="tcp,udp" ;;
        *) echo -e "${RED}无效选择${NC}"; return 1 ;;
    esac

    echo -e "${GREEN}输入目标地址（例如：1.1.1.1）：${NC}"
    read dest_addr
    if ! validate_ip "$dest_addr"; then
        echo -e "${RED}请输入有效的 IPv4 地址（示例: 1.1.1.1）${NC}"
        return 1
    fi
    table_name="ip"

    if ! nft list tables | grep -q "table $table_name nat"; then
        echo -e "${RED}nat 表不存在${NC}, ${GREEN}自动创建...${NC}"
        nft "add table $table_name nat" || { echo -e "${RED}创建 $table_name nat 表失败${NC}"; return 1; }
        nft "add chain $table_name nat prerouting { type nat hook prerouting priority 0 ; policy accept ; }" || { echo -e "${RED}创建 prerouting 链失败${NC}"; return 1; }
        nft "add chain $table_name nat postrouting { type nat hook postrouting priority 100 ; policy accept ; }" || { echo -e "${RED}创建 postrouting 链失败${NC}"; return 1; }
    fi

    echo -e "${GREEN}输入源端口（例如：80 或 100-110）：${NC}"
    read port
    if [[ $port =~ ^[0-9]+$ ]]; then
        echo -e "${GREEN}输入目标端口（例如：80）：${NC}"
        read dest_port
        proto_list=${protocol//,/ }
        for proto in $proto_list; do
            if ! nft add rule "$table_name" nat prerouting "$proto" dport "$port" counter dnat to "$dest_addr:$dest_port" 2>/dev/null; then
                echo -e "${RED}添加 $proto NAT 规则失败${NC}"
                return 1
            fi
        done
        echo -e "${GREEN}规则添加成功${NC}"
        echo -e "${GREEN}协议：$protocol, 源端口：$port, 目标地址：$dest_addr, 目标端口：$dest_port${NC}"
        add_snat_if_needed "$dest_addr"
    elif [[ $port =~ ^[0-9]+-[0-9]+$ ]]; then
        start_port=${port%-*}
        end_port=${port#*-}
        proto_list=${protocol//,/ }
        for proto in $proto_list; do
            if ! nft add rule "$table_name" nat prerouting "$proto" dport "{ $start_port-$end_port }" counter dnat to "$dest_addr" 2>/dev/null; then
                echo -e "${RED}添加 $proto NAT 范围规则失败${NC}"
                return 1
            fi
        done
        echo -e "${GREEN}规则添加成功${NC}"
        echo -e "${GREEN}协议：$protocol, 源端口：$start_port-$end_port, 目标地址：$dest_addr${NC}"
        add_snat_if_needed "$dest_addr"
    else
        echo -e "${RED}端口格式不正确${NC}"
        return 1
    fi
}

# 添加 SNAT 规则（仅支持 IPv4）
add_snat_if_needed() {
    local dest_addr=$1
    if ! check_snat_exists "$dest_addr"; then
        oif=$(ip -4 route show default | awk '{print $5}' | grep -v 'tun\|docker' | head -n1)
        if [ -n "$oif" ]; then
            table_name="ip"
            if ! nft list ruleset | grep -q "oifname \"$oif\" masquerade"; then
                nft add rule "$table_name" nat postrouting oifname "$oif" masquerade || { echo -e "${RED}添加 SNAT 规则失败${NC}"; return 1; }
                echo -e "${GREEN}添加了新的 SNAT 规则${NC}"
            fi
        else
            echo -e "${RED}无法找到合适的外网接口${NC}"
        fi
    fi
}

# 列出 NAT 规则
list_nat_rules() {
    echo -e "${RED}当前 NAT 规则：${NC}"
    nft list ruleset | grep nat | grep -E "^[[:space:]]*(tcp|udp|ip)" | awk '
    {
        if ($2 ~ /dport/) {
            protocol=$1
            port=$3
            for (i=4; i<=NF; i++) {
                if ($i ~ /dnat/) {
                    split($(i+2), addrport, ":")
                    if (length(addrport) > 1) {
                        print "\033[32m" NR ". 协议：" protocol ", 源端口：" port ", 目标地址：" addrport[1] ", 目标端口：" addrport[2] "\033[0m"
                    } else {
                        print "\033[32m" NR ". 协议：" protocol ", 源端口：" port ", 目标地址：" addrport[1] "\033[0m"
                    }
                    break
                }
            }
        } else if ($1 ~ /ip/ && $3 ~ /masquerade/) {
            print "\033[32m" NR ". SNAT 规则, 出接口：" $2 "\033[0m"
        }
    }'
}

# 删除 NAT 规则
delete_nat_rule() {
    echo -e "${YELLOW}当前 NAT 规则：${NC}"
    nft -a list ruleset | grep nat | grep -E "^[[:space:]]*(tcp|udp)" | awk '
    {
        if ($2 ~ /dport/) {
            protocol=$1
            port=$3
            for (i=4; i<=NF; i++) {
                if ($i ~ /dnat/) {
                    split($(i+2), addrport, ":")
                    if (length(addrport) > 1) {
                        print "\033[32m" NR ". 协议：" protocol " 源端口：" port " 目标地址：" addrport[1] " 目标端口：" addrport[2] " 句柄：" $(NF) "\033[0m"
                    } else {
                        print "\033[32m" NR ". 协议：" protocol " 源端口：" port " 目标地址：" addrport[1] " 句柄：" $(NF) "\033[0m"
                    }
                    break
                }
            }
        }
    }'
    read -p $'\e[31m请输入要删除的规则序号：\e[0m' rule_number
    rule_info=$(nft -a list ruleset | grep nat | grep -E "^[[:space:]]*(tcp|udp)" | awk -v num="$rule_number" 'NR==num {print $0}')
    if [ -n "$rule_info" ]; then
        handle=$(echo "$rule_info" | awk '{print $NF}')
        table_name="ip"
        if nft delete rule "$table_name" nat prerouting handle "$handle"; then
            echo -e "${GREEN}DNAT 规则已删除${NC}"
        else
            echo -e "${RED}删除 DNAT 规则失败${NC}"
        fi
    else
        echo -e "${RED}未找到对应的规则${NC}"
    fi
}

# 清空 NAT 规则（仅 IPv4）
clear_nat_rules() {
    nft flush table ip nat 2>/dev/null
    echo -e "${GREEN}NAT 规则已清空${NC}"
}

# 保存规则
save_rules() {
    mkdir -p /usr/local
    nft list ruleset > /usr/local/nft.conf
    echo -e "${GREEN}规则已保存到 /usr/local/nft.conf${NC}"
}

# 加载规则
load_rules() {
    if [ -f /usr/local/nft.conf ]; then
        nft -f /usr/local/nft.conf
        echo -e "${GREEN}规则已从 /usr/local/nft.conf 加载${NC}"
    else
        echo -e "${RED}未找到 /usr/local/nft.conf 文件${NC}"
    fi
}

# 卸载 NFT
uninstall_nft() {
    apt-get remove -y nftables
    echo -e "${RED}nft 已卸载${NC}"
}

# 开启端口
open_port() {
    local protocol=$1
    local ports=$2

    table_name="inet"
    chain_name="filter"
    if ! nft list tables | grep -q "table $table_name $chain_name"; then
        nft "add table $table_name $chain_name" || { echo -e "${RED}创建 inet filter 表失败${NC}"; return 1; }
        nft "add chain $table_name $chain_name input { type filter hook input priority 0 ; policy accept ; }" || { echo -e "${RED}创建 input 链失败${NC}"; return 1; }
        echo -e "${GREEN}创建 inet filter 表，默认策略为 accept${NC}"
    fi

    if ! nft list ruleset | grep -q "iifname \"lo\" accept"; then
        nft add rule "$table_name" "$chain_name" input iifname "lo" accept || { echo -e "${RED}添加本地回环规则失败${NC}"; return 1; }
        echo -e "${GREEN}已添加本地回环规则${NC}"
    fi

    if ! nft list ruleset | grep -q "ct state established,related accept"; then
        nft add rule "$table_name" "$chain_name" input ct state established,related accept || { echo -e "${RED}添加已建立连接规则失败${NC}"; return 1; }
        echo -e "${GREEN}已添加已建立连接规则${NC}"
    fi

    if ! nft list chain "$table_name" "$chain_name" input | grep -q "policy drop"; then
        nft "chain $table_name $chain_name input { policy drop ; }" || { echo -e "${RED}修改默认策略为 drop 失败${NC}"; return 1; }
        echo -e "${YELLOW}默认策略已改为 drop，仅允许明确开放的端口通过${NC}"
        
        if ! nft list chain "$table_name" "$chain_name" input | grep -q "tcp dport 22 accept"; then
            echo -e "${RED}建议放行 SSH 端口（默认 22）以保持服务器管理连接，是否放行？（y/n）${NC}"
            read -p "请选择: " ssh_confirm
            if [ "$ssh_confirm" = "y" ]; then
                nft add rule "$table_name" "$chain_name" input tcp dport 22 accept || { echo -e "${RED}放行 SSH 端口失败${NC}"; return 1; }
                echo -e "${GREEN}SSH 端口（22）已放行${NC}"
            else
                echo -e "${YELLOW}未放行 SSH 端口，请确保有其他方式管理服务器${NC}"
            fi
        fi
    fi

    IFS=',' read -ra PORTS <<< "$ports"
    for port in "${PORTS[@]}"; do
        if [[ $port =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start_port=${BASH_REMATCH[1]}
            end_port=${BASH_REMATCH[2]}
            port_range="${start_port}-${end_port}"
            for proto in ${protocol//,/ }; do
                if ! nft list chain "$table_name" "$chain_name" input | grep -q "$proto dport { $port_range } accept"; then
                    nft add rule "$table_name" "$chain_name" input "$proto" dport "{ $port_range }" accept || { echo -e "${RED}添加 $proto $port_range 规则失败${NC}"; return 1; }
                    echo -e "${GREEN}端口范围 $port_range ($proto) 已开启${NC}"
                else
                    echo -e "${YELLOW}端口范围 $port_range ($proto) 已放行${NC}"
                fi
            done
        elif [[ $port =~ ^[0-9]+$ ]]; then
            for proto in ${protocol//,/ }; do
                if ! nft list chain "$table_name" "$chain_name" input | grep -q "$proto dport $port accept"; then
                    nft add rule "$table_name" "$chain_name" input "$proto" dport "$port" accept || { echo -e "${RED}添加 $proto $port 规则失败${NC}"; return 1; }
                    echo -e "${GREEN}端口 $port ($proto) 已开启${NC}"
                else
                    echo -e "${YELLOW}端口 $port ($proto) 已放行${NC}"
                fi
            done
        else
            echo -e "${RED}无效端口格式：$port${NC}"
        fi
    done
}

# 列出已开启端口
list_open_ports() {
    echo -e "${RED}已开启的端口：${NC}"
    for proto in tcp udp; do
        echo -e "${YELLOW}${proto^^} 单端口：${NC}"
        nft list chain inet filter input | grep -E "$proto dport [0-9]+ accept" | awk '{print $3}' | sed 's/dport//g' | tr '\n' ' '
        echo
        echo -e "${YELLOW}${proto^^} 范围端口：${NC}"
        nft list chain inet filter input | grep -E "$proto dport [0-9]+-[0-9]+ accept" | awk '{print $3}' | sed 's/dport//g' | tr '\n' ' '
        echo
    done
}

# 关闭端口
close_port() {
    list_open_ports
    read -p $'\e[32m请输入要关闭的端口号或范围（用逗号分隔）：\e[0m' ports
    IFS=',' read -ra PORTS <<< "$ports"
    for port in "${PORTS[@]}"; do
        if [[ $port =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start_port=${BASH_REMATCH[1]}
            end_port=${BASH_REMATCH[2]}
            port_range="${start_port}-${end_port}"
            for proto in tcp udp; do
                handle=$(nft -a list chain inet filter input | awk "/$proto dport { $port_range } accept/{print \$NF}" | tail -n1)
                if [ -n "$handle" ]; then
                    nft delete rule inet filter input handle "$handle" || { echo -e "${RED}删除 $proto $port_range 规则失败${NC}"; return 1; }
                    echo -e "${GREEN}${proto^^} 端口范围 $port_range 已关闭${NC}"
                fi
            done
        elif [[ $port =~ ^[0-9]+$ ]]; then
            for proto in tcp udp; do
                handle=$(nft -a list chain inet filter input | awk "/$proto dport $port accept/{print \$NF}" | tail -n1)
                if [ -n "$handle" ]; then
                    nft delete rule inet filter input handle "$handle" || { echo -e "${RED}删除 $proto $port 规则失败${NC}"; return 1; }
                    echo -e "${GREEN}${proto^^} 端口 $port 已关闭${NC}"
                fi
            done
        else
            echo -e "${RED}无效端口格式：$port${NC}"
        fi
    done
}

# 禁用 Ping（支持 IPv4 和 IPv6）
disable_ping() {
    if ! nft list chain inet filter input | grep -q "ip protocol icmp drop"; then
        nft add rule inet filter input ip protocol icmp drop || { echo -e "${RED}禁用 IPv4 Ping 失败${NC}"; return 1; }
        echo -e "${GREEN}IPv4 Ping 已禁用${NC}"
    else
        echo -e "${YELLOW}IPv4 Ping 已禁用${NC}"
    fi
    if ! nft list chain inet filter input | grep -q "ip6 nexthdr ipv6-icmp drop"; then
        nft add rule inet filter input ip6 nexthdr ipv6-icmp drop || { echo -e "${RED}禁用 IPv6 Ping 失败${NC}"; return 1; }
        echo -e "${GREEN}IPv6 Ping 已禁用${NC}"
    else
        echo -e "${YELLOW}IPv6 Ping 已禁用${NC}"
    fi
}

# 允许 Ping（支持 IPv4 和 IPv6）
enable_ping() {
    handle=$(nft -a list chain inet filter input | awk '/ip protocol icmp drop/{print $NF}' | tail -n1)
    if [ -n "$handle" ]; then
        nft delete rule inet filter input handle "$handle" || { echo -e "${RED}启用 IPv4 Ping 失败${NC}"; return 1; }
        echo -e "${GREEN}IPv4 Ping 已允许${NC}"
    else
        echo -e "${YELLOW}IPv4 Ping 已允许${NC}"
    fi
    handle=$(nft -a list chain inet filter input | awk '/ip6 nexthdr ipv6-icmp drop/{print $NF}' | tail -n1)
    if [ -n "$handle" ]; then
        nft delete rule inet filter input handle "$handle" || { echo -e "${RED}启用 IPv6 Ping 失败${NC}"; return 1; }
        echo -e "${GREEN}IPv6 Ping 已允许${NC}"
    else
        echo -e "${YELLOW}IPv6 Ping 已允许${NC}"
    fi
}

# 开启所有端口
open_all_ports() {
    read -p $'\e[33m确定要开启所有端口吗？（y/n）：\e[0m' confirm
    if [ "$confirm" = "y" ]; then
        nft chain inet filter input '{ policy accept ; }' || { echo -e "${RED}开启所有端口失败${NC}"; return 1; }
        echo -e "${GREEN}所有端口已开启${NC}"
    else
        echo -e "${YELLOW}操作已取消${NC}"
    fi
}

# 清空所有开放端口
clear_all_open_ports() {
    read -p $'\e[33m确定要清空所有端口规则吗？（y/n）：\e[0m' confirm
    if [ "$confirm" = "y" ]; then
        nft flush chain inet filter input || { echo -e "${RED}清空端口规则失败${NC}"; return 1; }
        nft chain inet filter input '{ policy accept ; }' || { echo -e "${RED}恢复默认策略失败${NC}"; return 1; }
        echo -e "${GREEN}所有端口规则已清空，默认策略恢复为 accept${NC}"
    else
        echo -e "${YELLOW}操作已取消${NC}"
    fi
}

# 主菜单
main_menu() {
    while true; do
        show_nft_status
        echo -e "\n${MAGENTA}=== NFT 管理面板 ===${NC}"
        echo -e "${GREEN}1. 安装 NFT${NC}"
        echo -e "${YELLOW}2. 防火墙管理${NC}"
        echo -e "${YELLOW}3. NAT 管理${NC}"
        echo -e "${GREEN}4. 保存规则${NC}"
        echo -e "${GREEN}5. 加载规则${NC}"
        echo -e "${RED}6. 卸载 NFT${NC}"
        echo -e "${RED}0. 退出${NC}"
        read -p $'\e[32m请选择一个选项：\e[0m' choice
        case $choice in
            1) install_nft ;;
            2) firewall_menu ;;
            3) nat_menu ;;
            4) save_rules ;;
            5) load_rules ;;
            6) uninstall_nft ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
    done
}

# NAT 管理菜单
nat_menu() {
    while true; do
        echo -e "\n${BLUE}=== NAT 管理菜单 ===${NC}"
        echo -e "${GREEN}1. 添加 NAT 规则${NC}"
        echo -e "${GREEN}2. 列出 NAT 规则${NC}"
        echo -e "${YELLOW}3. 删除 NAT 规则${NC}"
        echo -e "${RED}4. 清空 NAT 规则${NC}"
        echo -e "${GREEN}0. 返回主菜单${NC}"
        read -p $'\e[32m请选择一个选项：\e[0m' choice
        case $choice in
            1) add_nat_rule ;;
            2) list_nat_rules ;;
            3) delete_nat_rule ;;
            4) clear_nat_rules ;;
            0) break ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
    done
}

# 防火墙管理菜单
firewall_menu() {
    while true; do
        echo -e "\n${BLUE}=== 防火墙管理菜单 ===${NC}"
        echo -e "${GREEN}1. 开启端口${NC}"
        echo -e "${GREEN}2. 列出已开启端口${NC}"
        echo -e "${RED}3. 关闭端口${NC}"
        echo -e "${YELLOW}4. 禁用 Ping${NC}"
        echo -e "${YELLOW}5. 允许 Ping${NC}"
        echo -e "${RED}6. 开启所有端口${NC}"
        echo -e "${RED}7. 清空所有开放端口${NC}"
        echo -e "${GREEN}0. 返回主菜单${NC}"
        read -p $'\e[32m请选择一个选项：\e[0m' choice
        case $choice in
            1)
                echo -e "${GREEN}选择协议：${NC}"
                echo -e "${GREEN}1. TCP${NC}"
                echo -e "${GREEN}2. UDP${NC}"
                echo -e "${GREEN}3. TCP/UDP${NC}"
                read -p "请选择: " protocol_choice
                case $protocol_choice in
                    1) protocol="tcp" ;;
                    2) protocol="udp" ;;
                    3) protocol="tcp,udp" ;;
                    *) echo -e "${RED}无效选择${NC}"; continue ;;
                esac
                read -p $'\e[32m请输入端口号或范围，多端口用 , 隔开（例如：80,440 或 100-200）：\e[0m' ports
                open_port "$protocol" "$ports"
                ;;
            2) list_open_ports ;;
            3) close_port ;;
            4) disable_ping ;;
            5) enable_ping ;;
            6) open_all_ports ;;
            7) clear_all_open_ports ;;
            0) break ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
    done
}

# 启动主菜单
main_menu
