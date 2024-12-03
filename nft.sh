#!/bin/bash

#nft 状态检测
check_nft() {
    if ! command -v nft &> /dev/null; then
        echo -e "\e[31mnft 未安装\e[0m"
        return 1
    fi

    nft_status=$(systemctl is-active nftables)
    case $nft_status in
        active)   echo -e "\e[32m 已安装  ●  正在运行\e[0m"; return 0 ;;
        inactive) echo -e "\e[32m 已安装  \e[31m●  未运行\e[0m"; return 2 ;;
        *)        echo -e "\e[32m 已安装  \e[33m●  状态未知\e[0m"; return 3 ;;
    esac
}
function show_nft_status() {
    sleep 0.2
    nft_status=$(check_nft)
    echo -e "\n\e[33mnft状态  →\e[0m $nft_status"
}

# 函数：启用 IP 转发
enable_ip_forward() {
    if [ ! -f /proc/sys/net/ipv4/ip_forward ] || [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
        echo "1" > /proc/sys/net/ipv4/ip_forward
        echo -e "\e[32m已开启 IP 转发功能\e[0m"
    else
        echo -e "\e[32mIP 转发功能已开启\e[0m"
    fi
}

# 函数：安装 nft
install_nft() {
    apt-get update && apt-get install -y nftables
    enable_ip_forward
    systemctl start nftables
    echo -e "\e[32mnft 安装完成\e[0m"
}

# 函数：检查 SNAT 规则是否已存在
check_snat_exists() {
    local dest_addr=$1
    if nft list table nat | grep -q "ip daddr $dest_addr snat to"; then
        return 0
    else
        return 1
    fi
}

# 函数：检查是否为有效的 IP 地址
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        # IPv4
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ $i -lt 0 ] || [ $i -gt 255 ]; then
                return 1
            fi
        done
        return 0
    elif [[ $ip =~ ^[0-9a-fA-F:]+$ ]]; then
        # IPv6
        if ip -6 route get $ip &>/dev/null; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}


# 修改函数：添加 NAT 规则
add_nat_rule() {
    echo -e "\e[32m选择协议：\e[0m"
    echo -e "\e[32m1. TCP\e[0m"
    echo -e "\e[32m2. UDP\e[0m"
    echo -e "\e[32m3. TCP/UDP\e[0m"
    read protocol
    case $protocol in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        3) protocol="tcp,udp" ;;
        *) echo -e "\e[31m无效选择\e[0m"; return ;;
    esac

    # 检查并创建必要的表和链
    if ! nft list tables | grep -q "table ip nat"; then
        echo -e "\e[31mnat表不存在\e[0m, \e[32m自动创建nat表...\e[0m"
        nft add table nat
        nft 'add chain nat prerouting { type nat hook prerouting priority 0; policy accept; }'
        nft 'add chain nat postrouting { type nat hook postrouting priority 100; policy accept; }'
    fi

    echo -e "\e[32m输入源端口（例如：80或100-110）：\e[0m"
    read port
    if [[ $port =~ ^[0-9]+$ ]]; then
        # 单端口
        echo -e "\e[32m输入目标地址（例如：1.1.1.1 或 2001:db8::1）：\e[0m"
        read dest_addr
        if ! validate_ip "$dest_addr"; then
            echo -e "\e[31m请输入标准地址格式\e[0m"
            return
        fi
        echo -e "\e[32m输入目标端口（例如：80）：\e[0m"
        read dest_port
        if [[ $protocol == "tcp,udp" ]]; then
            if nft add rule nat prerouting tcp dport $port counter dnat to $dest_addr:$dest_port && \
               nft add rule nat prerouting udp dport $port counter dnat to $dest_addr:$dest_port; then
                echo -e "\e[1;32m规则添加成功\e[0m"
                echo -e "\e[32m协议：$protocol, 源端口：$port, 目标地址：$dest_addr, 目标端口：$dest_port\e[0m"
                add_snat_if_needed "$dest_addr"
            else
                echo -e "\e[1;31m规则添加失败：$(nft -a list ruleset | grep -E "error")\e[0m"
            fi
        else
            if nft add rule nat prerouting $protocol dport $port counter dnat to $dest_addr:$dest_port; then
                echo -e "\e[1;32m规则添加成功\e[0m"
                echo -e "\e[32m协议：$protocol, 源端口：$port, 目标地址：$dest_addr, 目标端口：$dest_port\e[0m"
                add_snat_if_needed "$dest_addr"
            else
                echo -e "\e[1;31m规则添加失败：$(nft -a list ruleset | grep -E "error")\e[0m"
            fi
        fi
    elif [[ $port =~ ^[0-9]+-[0-9]+$ ]]; then
        # 范围端口
        start_port=${port%-*}
        end_port=${port#*-}
        echo "输入目标地址（例如：192.168.1.100 或 2001:db8::1）："
        read dest_addr
        if ! validate_ip "$dest_addr"; then
            echo -e "\e[31m请输入标准地址格式\e[0m"
            return
        fi
        if [[ $protocol == "tcp,udp" ]]; then
            if nft add rule nat prerouting tcp dport { $start_port-$end_port } counter dnat to $dest_addr && \
               nft add rule nat prerouting udp dport { $start_port-$end_port } counter dnat to $dest_addr; then
                echo -e "\e[1;32m规则添加成功\e[0m"
                echo -e "\e[32m协议：$protocol, 源端口：$start_port-$end_port, 目标地址：$dest_addr\e[0m"
                add_snat_if_needed "$dest_addr"
            else
                echo -e "\e[1;31m规则添加失败：$(nft -a list ruleset | grep -E "error")\e[0m"
            fi
        else
            if nft add rule nat prerouting $protocol dport { $start_port-$end_port } counter dnat to $dest_addr; then
                echo -e "\e[1;32m规则添加成功\e[0m"
                echo -e "\e[32m协议：$protocol, 源端口：$start_port-$end_port, 目标地址：$dest_addr\e[0m"
                add_snat_if_needed "$dest_addr"
            else
                echo -e "\e[1;31m规则添加失败：$(nft -a list ruleset | grep -E "error")\e[0m"
            fi
        fi
    else
        echo -e "\e[1;31m端口格式不正确\e[0m"
    fi
}

# 修改函数：检查并添加 SNAT 规则（如果需要）
add_snat_if_needed() {
    local dest_addr=$1
    if ! check_snat_exists "$dest_addr"; then
        # 获取外网接口，排除tun和docker网络
        oif=$(ip -o -4 addr show | grep -v 'tun\|docker' | awk '{print $2}' | grep -v 'lo' | head -n1)
        if [ -n "$oif" ]; then
            # 检查是否已经有匹配指定接口的masquerade规则
            if ! nft list ruleset | grep -q "oifname \"$oif\" masquerade"; then
                # 添加masquerade规则
                nft add rule ip nat postrouting oifname "$oif" masquerade
                echo -e "\e[1;32m添加了新的SNAT规则\e[0m"
            fi            
        else
            echo -e "\e[1;31m无法找到合适的外网接口\e[0m"
        fi
    fi
}

# 函数：列出 NAT 规则
list_nat_rules() {
    echo -e "\e[31m列出已有规则：\e[0m"
    nft list ruleset | grep nat | grep -E "^[[:space:]]*(tcp|udp|ip)" | awk '{
        if ($2 ~ /dport/ || $2 ~ /daddr/) {
            protocol=$1
            if ($2 ~ /dport/) {
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
            } else if ($2 ~ /daddr/) {
                dest_addr=$3
                print "\033[32m" NR ". 协议：" protocol ", 目标地址：" dest_addr ", SNAT 规则\033[0m"
            }
        }
    }'
}

# 函数：删除 NAT 规则
delete_nat_rule() {
    echo -e "\e[33m列出已有规则：\e[0m"
    nft -a list table nat | grep -E "^[[:space:]]*(tcp|udp)" | awk '{
        if ($2 ~ /dport/) {
            protocol=$1
            port=$3
            for (i=4; i<=NF; i++) {
                if ($i ~ /dnat/) {
                    split($(i+2), addrport, ":")
                    if (length(addrport) > 1) {
                        print "\033[32m" NR ". 协议：" protocol " 源端口：" port " 目标地址：" addrport[1] " 目标端口：" addrport[2] " 规则句柄：" $(NF) "\033[0m"
                    } else {
                        print "\033[32m" NR ". 协议：" protocol " 目标地址：" addrport[1] " 规则句柄：" $(NF) "\033[0m"
                    }
                    break
                }
            }
        }
    }'
    echo -e "\e[31m请输入要删除的规则序号\e[0m"
    read rule_number
    rule_info=$(nft -a list table nat | grep -E "^[[:space:]]*(tcp|udp)" | awk -v num=$rule_number 'NR==num {print $0}')
    if [ -n "$rule_info" ]; then
        port=$(echo "$rule_info" | awk '{print $3}')
        dest_addr=$(echo "$rule_info" | awk '{
            for (i=4; i<=NF; i++) {
                if ($i ~ /dnat/) {
                    split($(i+2), addrport, ":")
                    print addrport[1]
                    break
                }
            }
        }')
        handle=$(echo "$rule_info" | awk '{print $NF}')
        if [ -n "$handle" ]; then
            if nft delete rule nat prerouting handle $handle; then
                echo -e "\e[32mDNAT 规则已删除\e[0m"
                
                # 检查是否有其他 DNAT 规则使用同一个目标地址
                other_dnat=$(nft list table nat | grep -E "^[[:space:]]*(tcp|udp)" | awk -v dest_addr=$dest_addr '{
                    if ($2 ~ /dport/) {
                        for (i=4; i<=NF; i++) {
                            if ($i ~ /dnat/) {
                                split($(i+2), addrport, ":")
                                if (addrport[1] == dest_addr) {
                                    print "\033[32m有其他规则使用此目标地址，SNAT 规则不会被删除\033[0m"
                                    exit 1
                                }
                            }
                        }
                    }
                }')
                
                if [ -z "$other_dnat" ]; then
                    # 如果没有其他规则使用此目标地址，则删除对应的 SNAT 规则
                    snat_handle=$(nft -a list table nat | grep -E "^[[:space:]]*(ip)" | awk -v dest_addr=$dest_addr '{
                        if ($2 ~ /saddr/ && $3 == dest_addr) {
                            print $NF
                            exit
                        }
                    }')
                    if [ -n "$snat_handle" ]; then
                        if nft delete rule nat postrouting handle $snat_handle; then
                            echo -e "\e[32m对应的 SNAT 规则已删除\e[0m"
                        else
                            echo -e "\e[31m删除对应的 SNAT 规则失败\e[0m"
                        fi
                    else
                        echo -e "\e[31m未找到对应的 SNAT 规则\e[0m"
                    fi
                fi
            else
                echo -e "\e[31m删除 DNAT 规则失败\e[0m"
            fi
        else
            echo -e "\e[31m未找到对应的 DNAT 规则句柄\e[0m"
        fi
    else
        echo -e "\e[31m未找到对应的规则信息\e[0m"
    fi
}

# 函数：清空 NAT 规则
clear_nat_rules() {
    nft flush table nat
    echo -e "\e[32mNAT 规则已清空\e[0m"
}

# 函数：保存 NAT 规则
save_rules() {
    if [ ! -d /usr/local ]; then
        mkdir -p /usr/local
    fi
    nft list ruleset > /usr/local/nft.conf
    echo -e "\e[32m现有规则已保存到 /usr/local/nft.conf\e[0m"
}

# 函数：加载 NAT 规则
load_rules() {
    if [ -f /usr/local/nft.conf ]; then
        nft -f /usr/local/nft.conf
        echo -e "\e[32m规则已从 /usr/local/nft.conf 加载\e[0m"
    else
        echo -e "\e[31m未找到 /usr/local/nft.conf 文件\e[0m"
    fi
}

# 函数：卸载 nft
uninstall_nft() {
    apt-get remove -y nftables
    echo -e "\e[31;1mnft 已卸载\e[0m"
}

# 函数：开启端口
function open_port() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo -e "\033[32m请提供协议（tcp/udp/tcp,udp）和端口号或端口范围。\033[0m"
        return 1
    fi

    protocol=$1
    ports=$2

    # 检查本地回环接口规则是否存在，如果不存在则添加
    add_local_loopback_rule

    # 检查 input 链的默认策略是否为 drop
    if ! nft list chain inet filter input | grep -q "policy drop"; then
        nft chain inet filter input '{ policy drop; }'
    fi

    # 添加允许已建立连接的规则，如果不存在
    if ! nft list ruleset | grep -q "ct state established,related accept"; then
        nft add rule inet filter input ct state established,related accept
        if [ $? -eq 0 ]; then
            echo -e "\e[32m已添加允许已建立连接的规则。\e[0m"
        else
            echo -e "\e[32m添加允许已建立连接的规则失败。\e[0m"
        fi
    fi

    # 获取所有已放行的端口和范围
    open_ports_tcp=$(nft list ruleset | grep -E "tcp dport [0-9]+ accept" | awk '{print $3}' | sed 's/dport//g')
    open_ports_udp=$(nft list ruleset | grep -E "udp dport [0-9]+ accept" | awk '{print $3}' | sed 's/dport//g')
    open_ranges_tcp=$(nft list ruleset | grep -E "tcp dport [0-9]+-[0-9]+ accept" | awk '{print $3}' | sed 's/dport//g')
    open_ranges_udp=$(nft list ruleset | grep -E "udp dport [0-9]+-[0-9]+ accept" | awk '{print $3}' | sed 's/dport//g')

    IFS=',' read -ra PORTS <<< "$ports"
    for port in "${PORTS[@]}"; do
        if [[ $port =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start_port=${BASH_REMATCH[1]}
            end_port=${BASH_REMATCH[2]}
            port_range="${start_port}-${end_port}"
            
            for proto in ${protocol//,/ }; do
                # 根据协议获取已放行端口和范围
                case $proto in
                    tcp)
                        open_ports=$open_ports_tcp
                        open_ranges=$open_ranges_tcp
                        ;;
                    udp)
                        open_ports=$open_ports_udp
                        open_ranges=$open_ranges_udp
                        ;;
                esac

                # 检查新范围是否与任何已有规则重叠
                for single_port in $open_ports; do
                    if [ $single_port -ge $start_port ] && [ $single_port -le $end_port ]; then
                        echo -e "\e[31m端口范围 $port_range ($proto) 包含已有端口 $single_port。\e[0m"
                        continue 2
                    fi
                done

                for range in $open_ranges; do
                    if [[ $range =~ ([0-9]+)-([0-9]+) ]]; then
                        range_start=${BASH_REMATCH[1]}
                        range_end=${BASH_REMATCH[2]}
                        
                        # 检查开始端口是否在已有范围内
                        if [ $start_port -ge $range_start ] && [ $start_port -le $range_end ]; then
                            echo -e "\e[31m端口 $start_port ($proto) 已被 $range_start-$range_end 覆盖。\e[0m"
                            continue 2
                        fi
                        
                        # 检查结束端口是否在已有范围内
                        if [ $end_port -ge $range_start ] && [ $end_port -le $range_end ]; then
                            echo -e "\e[31m端口 $end_port ($proto) 已被 $range_start-$range_end 覆盖。\e[0m"
                            continue 2
                        fi
                        
                        # 检查新范围是否与任何已有范围重叠
                        if [ $start_port -le $range_start ] && [ $end_port -ge $range_start ] || \
                           [ $start_port -le $range_end ] && [ $end_port -ge $range_end ] || \
                           [ $start_port -ge $range_start ] && [ $end_port -le $range_end ]; then
                            echo -e "\e[31m端口范围 $port_range ($proto) 与已有规则 $range_start-$range_end 重叠。\e[0m"
                            continue 2
                        fi
                    fi
                done
                
                # 如果没有被覆盖，则添加规则
                nft add rule inet filter input $proto dport ${port_range} accept
                if [ $? -eq 0 ]; then
                    echo -e "\e[32m端口范围 $port_range ($proto) 已开启。\e[0m"
                else
                    echo -e "\e[31m端口范围 $port_range ($proto) 开启失败。\e[0m"
                fi
            done
        elif [[ $port =~ ^[0-9]+$ ]]; then
            # 检查单个端口是否在任何已有范围内或已被开启
            for proto in ${protocol//,/ }; do
                case $proto in
                    tcp)
                        open_ports=$open_ports_tcp
                        open_ranges=$open_ranges_tcp
                        ;;
                    udp)
                        open_ports=$open_ports_udp
                        open_ranges=$open_ranges_udp
                        ;;
                esac

                if echo "$open_ports" | grep -q "$port"; then
                    echo -e "\e[32m端口 $port ($proto) 已被放行。\e[0m"
                else
                    # 检查端口是否在任何已有范围内
                    for range in $open_ranges; do
                        if [[ $range =~ ([0-9]+)-([0-9]+) ]]; then
                            range_start=${BASH_REMATCH[1]}
                            range_end=${BASH_REMATCH[2]}
                            if [ $port -ge $range_start ] && [ $port -le $range_end ]; then
                                echo -e "\e[31m端口 $port ($proto) 已被 $range_start-$range_end 覆盖。\e[0m"
                                continue 2
                            fi
                        fi
                    done
                    # 如果没有被覆盖，则添加规则
                    nft add rule inet filter input $proto dport $port accept
                    if [ $? -eq 0 ]; then
                        echo -e "\033[32m端口 $port ($proto) 已开启。\033[0m"
                    else
                        echo -e "\e[31m端口 $port ($proto) 开启失败。\e[0m"
                    fi
                fi
            done
        else
            echo -e "\e[31m无效的端口或端口范围格式：$port\e[0m"
        fi
    done
}

# 函数：添加本地回环接口规则
function add_local_loopback_rule() {
    if ! nft list ruleset | grep -q "iifname \"lo\" accept"; then
        nft add rule inet filter input iifname "lo" accept
        echo -e "${GREEN}已添加本地回环接口规则。${NC}"
    fi
}

# 函数：列出已开启的端口
function list_open_ports() {
    echo -e "\e[31m已开启的端口:\e[0m"

    # TCP单端口
    echo -e "\e[33mTCP单端口：\e[0m"
    nft list ruleset | grep -E 'tcp dport [0-9]+ accept' | awk '{print $3}' | sed 's/dport//g' | while read port; do
        echo -e "\e[32m$port  \e[0m"
    done | tr -d '\n' && echo

    # UDP单端口
    echo -e "\e[33mUDP单端口：\e[0m"
    nft list ruleset | grep -E 'udp dport [0-9]+ accept' | awk '{print $3}' | sed 's/dport//g' | while read port; do
        echo -e "\e[32m$port  \e[0m"
    done | tr -d '\n' && echo

    # TCP范围端口
    echo -e "\e[33mTCP范围端口：\e[0m"
    nft list ruleset | grep -E 'tcp dport [0-9]+-[0-9]+ accept' | awk '{print $3}' | sed 's/dport//g' | while read port; do
        echo -e "\e[32m$port  \e[0m"
    done | tr -d '\n' && echo

    # UDP范围端口
    echo -e "\e[33mUDP范围端口：\e[0m"
    nft list ruleset | grep -E 'udp dport [0-9]+-[0-9]+ accept' | awk '{print $3}' | sed 's/dport//g' | while read port; do
        echo -e "\e[32m$port  \e[0m"
    done | tr -d '\n' && echo
}

# 函数：关闭指定端口
function close_port() {
    # 列出已开启的端口
    list_open_ports
    read -p $'\e[32m请输入要关闭的端口号或端口范围（多个端口用逗号分隔）：\e[0m' ports

    # 解析端口范围和多个端口
    IFS=',' read -ra PORTS <<< "$ports"
    for port in "${PORTS[@]}"; do
        if [[ $port =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start_port=${BASH_REMATCH[1]}
            end_port=${BASH_REMATCH[2]}
            port_range="${start_port}-${end_port}"
            rule_handle_tcp=$(nft -a list ruleset | awk "/tcp dport ${port_range} accept/{print \$NF}" | tail -n1)
            rule_handle_udp=$(nft -a list ruleset | awk "/udp dport ${port_range} accept/{print \$NF}" | tail -n1)

            if [ -n "$rule_handle_tcp" ]; then
                nft delete rule inet filter input handle $rule_handle_tcp
                if [ $? -eq 0 ]; then
                    echo -e "\e[32mTCP端口范围 $port_range 已关闭。\e[0m"
                else
                    echo -e "\e[31mTCP端口范围 $port_range 关闭失败。\e[0m"
                fi
            elif [ -n "$rule_handle_udp" ]; then
                nft delete rule inet filter input handle $rule_handle_udp
                if [ $? -eq 0 ]; then
                    echo -e "\e[32mUDP端口范围 $port_range 已关闭。\e[0m"
                else
                    echo -e "\e[31mUDP端口范围 $port_range 关闭失败。\e[0m"
                fi
            else
                echo -e "\e[31m没有找到匹配的规则。\e[0m"
            fi
        elif [[ $port =~ ^[0-9]+$ ]]; then
            rule_handle_tcp=$(nft -a list ruleset | awk "/tcp dport $port accept/{print \$NF}" | tail -n1)
            rule_handle_udp=$(nft -a list ruleset | awk "/udp dport $port accept/{print \$NF}" | tail -n1)

            if [ -n "$rule_handle_tcp" ]; then
                nft delete rule inet filter input handle $rule_handle_tcp
                if [ $? -eq 0 ]; then
                    echo -e "\e[32mTCP端口 $port 已关闭。\e[0m"
                else
                    echo -e "\e[31mTCP端口 $port 关闭失败。\e[0m"
                fi
            elif [ -n "$rule_handle_udp" ]; then
                nft delete rule inet filter input handle $rule_handle_udp
                if [ $? -eq 0 ]; then
                    echo -e "\e[32mUDP端口 $port 已关闭。\e[0m"
                else
                    echo -e "\e[31mUDP端口 $port 关闭失败。\e[0m"
                fi
            else
                echo -e "\e[31m没有找到匹配的规则。\e[0m"
            fi
        else
            echo -e "\e[31m无效的端口或端口范围格式：$port \e[0m"
        fi
    done
}

# 函数：禁用Ping
function disable_ping() {
    # 获取链策略
    policy=$(nft list table inet filter | awk '/type filter hook input priority filter; policy/ {gsub(/;$/, "", $NF); print $NF}')
    
    # 如果链策略是accept，检查并添加禁止ping的规则
    if [ "$policy" = "accept" ]; then
        # IPv4
        if ! nft list ruleset | grep -q "icmp type echo-request drop"; then
            nft add rule inet filter input icmp type echo-request drop
            if [ $? -eq 0 ]; then
                echo -e "\e[32mIPv4 Ping已被禁用。\e[0m"
            else
                echo -e "\e[31mIPv4 Ping禁用失败。\e[0m"
            fi
        else
            echo -e "\e[33mIPv4 Ping已经是禁用状态。\e[0m"
        fi
        
        # IPv6
        if ! nft list ruleset | grep -q "ip6 nexthdr ipv6-icmp drop"; then
            nft add rule inet filter input ip6 nexthdr icmpv6 drop
            if [ $? -eq 0 ]; then
                echo -e "\e[32mIPv6 Ping已被禁用。\e[0m"
            else
                echo -e "\e[31mIPv6 Ping禁用失败。\e[0m"
            fi
        else
            echo -e "\e[33mIPv6 Ping已经是禁用状态。\e[0m"
        fi

    # 如果链策略是drop，检查并删除允许ping的规则
    elif [ "$policy" = "drop" ]; then
        # IPv4
        rule_handle=$(nft -a list ruleset | awk '/icmp type echo-request accept/{print $NF}' | tail -n1)
        if [ -n "$rule_handle" ]; then
            nft delete rule inet filter input handle "$rule_handle"
            echo -e "\e[32mIPv4 Ping已被禁用。\e[0m"
        else
            echo -e "\e[33mIPv4 Ping已经是禁用状态。\e[0m"
        fi
        
        # IPv6
        rule_handle=$(nft -a list ruleset | awk '/ip6 nexthdr ipv6-icmp accept/{print $NF}' | tail -n1)
        if [ -n "$rule_handle" ]; then
            nft delete rule inet filter input handle "$rule_handle"
            echo -e "\e[32mIPv6 Ping已被禁用。\e[0m"
        else
            echo -e "\e[33mIPv6 Ping已经是禁用状态。\e[0m"
        fi
    else
        echo -e "\e[31m无法确定filter链策略。\e[0m"
    fi
}

# 函数：允许Ping
function enable_ping() {
    # 获取链策略
    policy=$(nft list table inet filter | awk '/type filter hook input priority filter; policy/ {gsub(/;$/, "", $NF); print $NF}')
    
    # 如果链策略是accept，检查并删除禁止ping的规则
    if [ "$policy" = "accept" ]; then
        # IPv4
        rule_handle=$(nft -a list ruleset | awk '/icmp type echo-request drop/{print $NF}' | tail -n1)
        if [ -n "$rule_handle" ]; then
            nft delete rule inet filter input handle "$rule_handle"
            echo -e "\e[32mIPv4 Ping已被允许。\e[0m"
        else
            echo -e "\e[33mIPv4 Ping已经是允许状态。\e[0m"
        fi
        
        # IPv6
        rule_handle=$(nft -a list ruleset | awk '/ip6 nexthdr ipv6-icmp drop/{print $NF}' | tail -n1)
        if [ -n "$rule_handle" ]; then
            nft delete rule inet filter input handle "$rule_handle"
            echo -e "\e[32mIPv6 Ping已被允许。\e[0m"
        else
            echo -e "\e[33mIPv6 Ping已经是允许状态。\e[0m"
        fi
    # 如果链策略是drop，检查并添加允许ping的规则
    elif [ "$policy" = "drop" ]; then
        # IPv4
        if ! nft list ruleset | grep -q "icmp type echo-request accept"; then
            nft add rule inet filter input icmp type echo-request accept
            if [ $? -eq 0 ]; then
                echo -e "\e[32mIPv4 Ping已被允许。\e[0m"
            else
                echo -e "\e[31mIPv4 Ping允许失败。\e[0m"
            fi
        else
            echo -e "\e[33mIPv4 Ping已经是允许状态。\e[0m"
        fi
        
        # IPv6
        if ! nft list ruleset | grep -q "ip6 nexthdr ipv6-icmp accept"; then
            nft add rule inet filter input ip6 nexthdr ipv6-icmp accept
            if [ $? -eq 0 ]; then
                echo -e "\e[32mIPv6 Ping已被允许。\e[0m"
            else
                echo -e "\e[31mIPv6 Ping允许失败。\e[0m"
            fi
        else
            echo -e "\e[33mIPv6 Ping已经是允许状态。\e[0m"
        fi
    else
        echo -e "\e[31m无法确定filter链策略。\e[0m"
    fi
}

# 函数：开启所有端口
function open_all_ports() {
    read -p $'\e[33m确定要开启所有端口吗？\e[31m（y/n）\e[0m: ' confirm
    if [ "$confirm" = "y" ]; then
        nft chain inet filter input '{ policy accept; }'
        echo -e "\e[32m所有端口已开启。\e[0m"
    else
        echo -e "\e[33m操作已取消。\e[0m"
    fi
}

# 函数：清空所有开放的端口
function clear_all_open_ports() {
    read -p $'\e[33m确定要清空所有端口吗？\e[31m（y/n）\e[0m: ' confirm
    if [ "$confirm" = "y" ]; then
        # 更改input链的默认策略为accept
        nft chain inet filter input '{ policy accept; }'
        # 清空inet filter input链中的所有规则
        nft flush chain inet filter input
        
        if [ $? -eq 0 ]; then
            echo -e "\e[32m所有端口规则已被清空，并将input链策略改为accept。\e[0m"
        else
            echo -e "\e[31m清空端口规则失败。\e[0m"
        fi
    else
        echo -e "\e[33m操作已取消。\e[0m"
    fi
}

# 主菜单
main_menu() {
    while true; do
	   show_nft_status
        echo -e "\n\e[1;95mnft 管理面板:\e[0m"
        echo -e "\e[32m1. 安装 nft\e[0m"
        echo -e "\e[33m2. 防火墙\e[0m"
        echo -e "\e[33m3. nat管理\e[0m"
        echo -e "\e[32m4. 保存规则\e[0m"
        echo -e "\e[32m5. 加载规则\e[0m"
        echo -e "\e[31m6. 卸载 nft\e[0m"
        echo -e "\e[31m0. 退出\e[0m"
        echo -e "\e[32m请输入一个选项：\e[0m"
        read choice

        case $choice in
            1) install_nft ;;
            2) firewall_menu ;;
            3) nat_menu ;;
            4) save_rules ;;
            5) load_rules ;;
            6) uninstall_nft ;;
            0) exit 0 ;;
            *) echo -e "\e[31m无效选择，请重新输入\e[0m" ;;
        esac
    done
}

# NAT 菜单
nat_menu() {
    while true; do
        echo -e "\n\e[1;34mNAT 管理菜单:\e[0m"
        echo -e "\e[32m1. 添加nat规则\e[0m"
        echo -e "\e[32m2. 列出nat规则\e[0m"
        echo -e "\e[33m3. 删除nat规则\e[0m"
        echo -e "\e[31m4. 清空nat规则\e[0m"
        echo -e "\e[32m0. 返回主菜单\e[0m"
        read -p $'\e[32m请选择一个选项: \e[0m' nat_choice
        case $nat_choice in
            1) add_nat_rule ;;
            2) list_nat_rules ;;
            3) delete_nat_rule ;;
            4) clear_nat_rules ;;
            0) break ;;
            *) echo -e "\e[31m无效选择，请重新输入\e[0m" ;;
        esac
    done
}

# 防火墙菜单
firewall_menu() {
    while true; do
        echo -e "\n\e[1;34m防火墙管理菜单:\e[0m"
        echo -e "\e[32m1. 开启端口\e[0m"
        echo -e "\e[32m2. 已开启端口\e[0m"
        echo -e "\e[31m3. 关闭端口\e[0m"
        echo -e "\e[33m4. 禁用Ping\e[0m"
        echo -e "\e[33m5. 允许Ping\e[0m"
        echo -e "\e[31m6. 开启所有端口\e[0m"
        echo -e "\e[31m7. 清空所有开放的端口\e[0m"
        echo -e "\e[32m0. 返回主菜单\e[0m"
        read -p $'\e[32m请选择一个选项: \e[0m' choice

        case $choice in
            1) 
                echo -e "\e[1;31m请选择协议：\e[0m"
                echo -e "\e[32m1. TCP\e[0m"
                echo -e "\e[32m2. UDP\e[0m"
                echo -e "\e[32m3. TCP/UDP\e[0m"
                read protocol_choice
                case $protocol_choice in
                    1) protocol="tcp" ;;
                    2) protocol="udp" ;;
                    3) protocol="tcp,udp" ;;
                    *) echo -e "\e[31m无效选择，请重新输入\e[0m"; continue ;;
                esac

                echo "请输入端口号或端口范围（例如：80或100-200）："
                read ports
                open_port $protocol $ports
                ;;
            2) list_open_ports ;;
            3) close_port ;;
            4) disable_ping ;;
            5) enable_ping ;;
            6) open_all_ports ;;
            7) clear_all_open_ports ;;
            0) break ;;
            *) echo -e "\e[31m无效选择，请重新输入\e[0m" ;;
        esac
    done
}

# 运行主菜单
main_menu
