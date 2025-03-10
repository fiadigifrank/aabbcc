#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN='\033[0m'

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt-get -y update" "apt-get -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意：请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" 
    if [[ -n $SYS ]]; then
        break
    fi
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
        SYSTEM="${RELEASE[int]}"
        if [[ -n $SYSTEM ]]; then
            break
        fi
    fi
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统，请使用主流的操作系统" && exit 1

back2menu() {
    echo ""
    green "所选命令操作执行完成"
    read -rp "请输入“y”退出，或按任意键回到主菜单：" back2menuInput
    case "$back2menuInput" in
        y) exit 1 ;;
        *) menu ;;
    esac
}

install_base(){
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo socat
    if [[ $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_INSTALL[int]} cronie
        systemctl start crond
        systemctl enable crond
    else
        ${PACKAGE_INSTALL[int]} cron
        systemctl start cron
        systemctl enable cron
    fi
}

install_acme(){
    install_base
    read -rp "请输入注册邮箱（例：admin@gmail.com，或留空自动生成一个gmail邮箱）：" acmeEmail
    if [[ -z $acmeEmail ]]; then
        autoEmail=$(date +%s%N | md5sum | cut -c 1-16)
        acmeEmail=$autoEmail@gmail.com
        yellow "已取消输入，使用自动生成的gmail邮箱：$acmeEmail"
    fi
    curl https://get.acme.sh | sh -s email=$acmeEmail
    source ~/.bashrc
    bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    if [[ -n $(~/.acme.sh/acme.sh -v 2>/dev/null) ]]; then
        green "Acme.sh证书申请脚本安装成功！"
    else
        red "抱歉，Acme.sh证书申请脚本安装失败"
        green "建议如下："
        yellow "1. 检查VPS的网络环境"
        yellow "2. 脚本可能跟不上时代，建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
    fi
    back2menu
}

check_80(){
    # 感谢Wulabing前辈提供的检查80端口思路
    # Source: https://github.com/wulabing/Xray_onekey

    if [[ -z $(type -P lsof) ]]; then
        ${PACKAGE_UPDATE[int]}
        ${PACKAGE_INSTALL[int]} lsof
    fi

    yellow "检查 80 端口是否占用..."
    sleep 1

    if [[  $(lsof -i:"80" | grep -i -c "listen") -eq 0 ]]; then
        green "目前 80 端口未被占用"
        sleep 1
    else
        red "检测到 80 端口被其他程序被占用，以下为 80 端口的占用信息"
        lsof -i:"80"
        read -rp "如需结束占用进程请按Y，按其他键则退出 [Y/N]：" yn
        if [[ $yn =~ "Y"|"y" ]]; then
            lsof -i:"80" | awk '{print $2}' | grep -v "PID" | xargs kill -9
            sleep 1
        else
            exit 1
        fi
    fi
}

getSingleCert(){
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && red "未安装acme.sh，无法执行操作" && exit 1
    check_80
    WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    ipv4=$(curl -s4m8 https://ip.gs)
    ipv6=$(curl -s6m8 https://ip.gs)
    realipv4=$(curl -s4m8 http://ip.sb)
    realipv6=$(curl -s6m8 http://ip.sb)
    read -rp "请输入解析完成的域名:" domain
    [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
    green "已输入的域名：$domain" && sleep 1
    domainIP=$(curl -sm8 ipget.net/?ip=misaka.sama."$domain")
    if [[ -n $(echo $domainIP | grep nginx) ]]; then
        domainIP=$(curl -sm8 ipget.net/?ip="$domain")
        if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
            if [[ $domainIP == $realipv6 ]]; then
                # 二次确认，防止IPv6地址被ip.sb bug识别成IPv4地址
                if [[ -n $(echo $realipv6 | grep ":") && -z $(echo $realipv6 | grep ".") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6
                else
                    red "检测IP失败，请关闭Wgcf-WARP后再使用本脚本申请证书"
                    back2menu
                fi
            fi
            if [[ $domainIP == $realipv4 ]]; then
                # 二次确认，防止IPv4地址被ip.sb bug识别成IPv6地址
                if [[ -z $(echo $realipv4 | grep ":") && -n $(echo $realipv4 | grep ".") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256
                else
                    red "检测IP失败，请关闭Wgcf-WARP后再使用本脚本申请证书"
                    back2menu
                fi
            fi
        else
            if [[ $domainIP == $ipv6 ]]; then
                bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6
            fi
            if [[ $domainIP == $ipv4 ]]; then
                bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256
            fi
        fi

        if [[ -n $(echo $domainIP | grep nginx) ]]; then
            yellow "域名解析无效，请检查域名是否填写正确或稍等几分钟等待解析完成再执行脚本"
            exit 1
        elif [[ -n $(echo $domainIP | grep ":") || -n $(echo $domainIP | grep ".") ]]; then
            if [[ $domainIP != $ipv4 ]] && [[ $domainIP != $ipv6 ]] && [[ $domainIP != $realipv4 ]] && [[ $domainIP != $realipv6 ]]; then
                green "${domain} 解析结果：（$domainIP）"
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS)，其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 脚本可能跟不上时代，建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                exit 1
            fi
        fi
    else
        red "目前疑似使用泛域名解析，请使用泛域名申请模式"
        back2menu
    fi
    bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/ssl/private.key --fullchain-file /root/ssl/cert.crt --ecc
    mkdir /home/deploy/FIACS/ssl
    cp /root/ssl/private.key /home/deploy/FIACS/ssl && cp /root/ssl/cert.crt /home/deploy/FIACS/ssl
    checktls
}

getDomainCert(){
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && red "未安装acme.sh，无法执行操作" && exit 1
    ipv4=$(curl -s4m8 https://ip.gs)
    ipv6=$(curl -s6m8 https://ip.gs)
    read -rp "请输入需要申请证书的泛域名（输入格式：example.com）：" domain
    [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
    if [[ $(echo ${domain:0-2}) =~ cf|ga|gq|ml|tk ]]; then
        red "检测为Freenom免费域名，由于CloudFlare API不支持，故无法使用本模式申请！"
        back2menu
    fi
    read -rp "请输入CloudFlare Global API Key：" GAK
    [[ -z $GAK ]] && red "未输入CloudFlare Global API Key，无法执行操作！" && exit 1
    export CF_Key="$GAK"
    read -rp "请输入CloudFlare的登录邮箱：" CFemail
    [[ -z $domain ]] && red "未输入CloudFlare的登录邮箱，无法执行操作！" && exit 1
    export CF_Email="$CFemail"
    if [[ -z $ipv4 ]]; then
        bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d "*.${domain}" -d "${domain}" -k ec-256 --listen-v6
    else
        bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d "*.${domain}" -d "${domain}" -k ec-256
    fi
    bash ~/.acme.sh/acme.sh --install-cert -d "*.${domain}" --key-file /root/ssl/private.key --fullchain-file /root/ssl/cert.crt --ecc
    mkdir /home/deploy/FIACS/ssl
    cp /root/ssl/private.key /home/deploy/FIACS/ssl && cp /root/ssl/cert.crt /home/deploy/FIACS/ssl
    checktls
}

getSingleDomainCert(){
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && red "未安装Acme.sh，无法执行操作" && exit 1
    ipv4=$(curl -s4m8 https://ip.gs)
    ipv6=$(curl -s6m8 https://ip.gs)
    read -rp "请输入需要申请证书的域名：" domain
    if [[ $(echo ${domain:0-2}) =~ cf|ga|gq|ml|tk ]]; then
        red "检测为Freenom免费域名，由于CloudFlare API不支持，故无法使用本模式申请！"
        back2menu
    fi
    read -rp "请输入CloudFlare Global API Key：" GAK
    [[ -z $GAK ]] && red "未输入CloudFlare Global API Key，无法执行操作！" && exit 1
    export CF_Key="$GAK"
    read -rp "请输入CloudFlare的登录邮箱：" CFemail
    [[ -z $domain ]] && red "未输入CloudFlare的登录邮箱，无法执行操作！" && exit 1
    export CF_Email="$CFemail"
    if [[ -z $ipv4 ]]; then
        bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" -k ec-256 --listen-v6
    else
        bash ~/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" -k ec-256
    fi
    bash ~/.acme.sh/acme.sh --install-cert -d "${domain}" --key-file /root/ssl/private.key --fullchain-file /root/ssl/cert.crt --ecc
    mkdir /home/deploy/FIACS/ssl
    cp /root/ssl/private.key /home/deploy/FIACS/ssl && cp /root/ssl/cert.crt /home/deploy/FIACS/ssl
    checktls
}

checktls() {
    if [[ -f /root/ssl/cert.crt && -f /root/ssl/rivate.key ]]; then
        if [[ -s /root/ssl/cert.crt && -s /root/ssl/private.key ]]; then
            sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
            echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
            green "证书申请成功！脚本申请到的证书（cert.crt）和私钥（private.key）已保存到 /root/ssl & /home/deploy/MSSC/ACID/QA/ssl/ 文件夹"
            yellow "证书crt路径如下：/root/ssl/cert.crt /home/deploy/MSSC/ACID/QA/ssl/cert.crt"
            yellow "私钥key路径如下：/root/ssl/private.key /home/deploy/MSSC/ACID/QA/ssl/private.key"
            back2menu
        else
            red "抱歉，证书申请失败"
            green "建议如下："
            yellow "1. 自行检测防火墙是否打开，如使用80端口申请模式时，请关闭防火墙或放行80端口"
            yellow "2. 同一域名多次申请可能会触发Let's Encrypt官方风控，请尝试使用脚本菜单的9选项更换证书颁发机构，再重试申请证书，或更换域名、或等待7天后再尝试执行脚本"
            yellow "3. 脚本可能跟不上时代，建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
            back2menu
        fi
    fi
}

view_cert(){
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "未安装acme.sh，无法执行操作" && exit 1
    bash ~/.acme.sh/acme.sh --list
    back2menu
}

revoke_cert() {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "未安装acme.sh，无法执行操作" && exit 1
    bash ~/.acme.sh/acme.sh --list
    read -rp "请输入要撤销的域名证书（复制Main_Domain下显示的域名）:" domain
    [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
    if [[ -n $(bash ~/.acme.sh/acme.sh --list | grep $domain) ]]; then
        bash ~/.acme.sh/acme.sh --revoke -d ${domain} --ecc
        bash ~/.acme.sh/acme.sh --remove -d ${domain} --ecc
        rm -rf ~/.acme.sh/${domain}_ecc
        rm -f /root/ssl/cert.crt /root/ssl/private.key
        green "撤销${domain}的域名证书成功"
        back2menu
    else
        red "未找到你输入的${domain}域名证书，请自行检查！"
        back2menu
    fi
}

renew_cert() {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "未安装acme.sh，无法执行操作" && exit 1
    bash ~/.acme.sh/acme.sh --list
    read -rp "请输入要续期的域名证书（复制Main_Domain下显示的域名）:" domain
    [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
    if [[ -n $(bash ~/.acme.sh/acme.sh --list | grep $domain) ]]; then
        bash ~/.acme.sh/acme.sh --renew -d ${domain} --force --ecc
        checktls
        back2menu
    else
        red "未找到你输入的${domain}域名证书，请再次检查域名输入正确"
        back2menu
    fi
}

switch_provider(){
    yellow "请选择证书提供商, 默认通过 Letsencrypt.org 来申请证书 "
    yellow "如果证书申请失败, 例如一天内通过 Letsencrypt.org 申请次数过多, 可选 BuyPass.com 或 ZeroSSL.com 来申请."
    echo -e " ${GREEN}1.${PLAIN} Letsencrypt.org"
    echo -e " ${GREEN}2.${PLAIN} BuyPass.com"
    echo -e " ${GREEN}3.${PLAIN} ZeroSSL.com"
    read -rp "请选择证书提供商 [1-3，默认1]: " provider
    case $provider in
        2) bash ~/.acme.sh/acme.sh --set-default-ca --server buypass && green "切换证书提供商为 BuyPass.com 成功！" ;;
        3) bash ~/.acme.sh/acme.sh --set-default-ca --server zerossl && green "切换证书提供商为 ZeroSSL.com 成功！" ;;
        *) bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt && green "切换证书提供商为 Letsencrypt.org 成功！" ;;
    esac
    back2menu
}

uninstall() {
    [[ -z $(~/.acme.sh/acme.sh -v 2>/dev/null) ]] && yellow "未安装Acme.sh，卸载程序无法执行" && exit 1
    ~/.acme.sh/acme.sh --uninstall
    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
    rm -rf ~/.acme.sh
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                   ${RED}Acme  一键申请证书脚本${PLAIN}                  #"
    echo -e "# ${GREEN}作者${PLAIN}: Misaka No                                           #"
    echo -e "# ${GREEN}博客${PLAIN}: https://owo.misaka.rest                             #"
    echo -e "# ${GREEN}论坛${PLAIN}: https://vpsgo.co                                    #"
    echo -e "# ${GREEN}TG群${PLAIN}: https://t.me/misakanetcn                            #"
    echo -e "# ${GREEN}GitHub${PLAIN}: https://github.com/Misaka-blog                    #"
    echo -e "# ${GREEN}Bitbucket${PLAIN}: https://bitbucket.org/misakano7545             #"
    echo -e "# ${GREEN}GitLab${PLAIN}: https://gitlab.com/misaka-blog                    #"
    echo "#############################################################"
    echo ""
    echo -e "#     ${SHAN}請先 在 root 下 mkdir SSL 目錄${RES}                      #"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 安装 Acme.sh 域名证书申请脚本"
    echo -e " ${GREEN}2.${PLAIN} ${RED}卸载 Acme.sh 域名证书申请脚本${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} 申请单域名证书 ${YELLOW}(80端口申请)${PLAIN}"
    echo -e " ${GREEN}4.${PLAIN} 申请单域名证书 ${YELLOW}(CF API申请)${PLAIN} ${GREEN}(无需解析)${PLAIN} ${RED}(不支持freenom域名)${PLAIN}"
    echo -e " ${GREEN}5.${PLAIN} 申请泛域名证书 ${YELLOW}(CF API申请)${PLAIN} ${GREEN}(无需解析)${PLAIN} ${RED}(不支持freenom域名)${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}6.${PLAIN} 查看已申请的证书"
    echo -e " ${GREEN}7.${PLAIN} 撤销并删除已申请的证书"
    echo -e " ${GREEN}8.${PLAIN} 手动续期已申请的证书"
    echo -e " ${GREEN}9.${PLAIN} 切换证书颁发机构"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -rp "请输入选项 [0-9]:" NumberInput
    case "$NumberInput" in
        1) install_acme ;;
        2) uninstall ;;
        3) getSingleCert ;;
        4) getSingleDomainCert ;;
        5) getDomainCert ;;
        6) view_cert ;;
        7) revoke_cert ;;
        8) renew_cert ;;
        9) switch_provider ;;
        *) exit 1 ;;
    esac
}

menu

#1