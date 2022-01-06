{% if request.target == "clash" or request.target == "clashr" %}

port: {{ default(global.clash.http_port, "7890") }}
socks-port: {{ default(global.clash.socks_port, "7891") }}
allow-lan: {{ default(global.clash.allow_lan, "true") }}
mode: Rule
log-level: {{ default(global.clash.log_level, "info") }}
external-controller: :9090
{% if default(request.clash.dns, "") == "1" %}
dns:
  enabled: true
  listen: 1053
{% endif %}
{% if local.clash.new_field_name == "true" %}
proxies: ~
proxy-groups: ~
rules: ~
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}

{% endif %}
{% if request.target == "surge" %}

[General]
# --- GENERAL ---
# Wi-Fi Assist
wifi-assist = false

# Latency Benchmark
internet-test-url = http://wifi.vivo.com.cn/generate_204
proxy-test-url = http://cp.cloudflare.com/generate_204
test-timeout = 5

# TLS Engine
tls-provider = openssl

# GeoIP Database
geoip-maxmind-url = https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb
ipv6 = true

# Wi-Fi Access
allow-wifi-access = false
wifi-access-http-port = 6152
wifi-access-socks5-port = 6153

http-listen = 127.0.0.1:6152
socks5-listen = 127.0.0.1:6153

# Remote Controller
external-controller-access = BlankMagic@127.0.0.1:8888

# HTTP API & Web Dashboard
# http-api = X-key@0.0.0.0:6166
//本机浏览器输入127.0.0.1:6166
# http-api-web-dashboard = true

# Compatibility
# > 兼容模式
compatibility-mode = False
# > 跳过代理
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, passenger.t3go.cn, localhost, *.local
# > 排除简单主机名
exclude-simple-hostnames = true

# Experimental
network-framework = false

# DNS Server
dns-server = 223.5.5.5, 114.114.114.114, system
# > 从 /etc/hosts 读取 DNS 记录
read-etc-hosts = true
doh-server = https://dns2.spdio.xyz:3443/dns-query, https://dns.fiacloud.com:3443/dns-query, https://dns.alidns.com/dns-query, https://doh.pub/dns-query
# > DoH 请求通过代理策略执行
doh-follow-outbound-mode = false

# --- FIREWALL ---
# Routing
include-all-networks = false
include-local-networks = false

# --- ADVANCED ---
# Log Level
loglevel = notify
# 当遇到 REJECT 策略时返回错误页
show-error-page-for-reject = true
# Always Real IP Hosts
always-real-ip = link-ip.nextdns.io, msftconnecttest.com, msftncsi.com, *.msftconnecttest.com, *.msftncsi.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com, *.battlenet.com.cn, *.battlenet.com, *.blzstatic.cn, *.battle.net
# Hijack DNS
hijack-dns = 8.8.8.8:53, 8.8.4.4:53
# TCP Force HTTP Hosts
//KOOWO - 123.59.31.1,119.18.193.135, 122.14.246.33, 175.102.178.52
//TencentVideo - 116.253.24.*, 175.6.26.*, 220.169.153.*
force-http-engine-hosts = *.ott.cibntv.net, 123.59.31.1,119.18.193.135, 122.14.246.33, 175.102.178.52, 116.253.24.*, 175.6.26.*, 220.169.153.*
# VIF Excluded Routes
tun-excluded-routes = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 239.255.255.250/32
# VIF Included Routes
tun-included-routes = 192.168.1.12/32
# 当 Wi-Fi 不是首选网络时 SSID 组策略使用默认策略
use-default-policy-if-wifi-not-primary = false

[Script]
http-request https?:\/\/.*\.iqiyi\.com\/.*authcookie= script-path=https://raw.githubusercontent.com/NobyDa/Script/master/iQIYI-DailyBonus/iQIYI.js

[Host]
# Firebase Cloud Messaging
mtalk.google.com = 108.177.125.188
# Google Dl
dl.google.com = server:119.29.29.29
dl.l.google.com = server:119.29.29.29

[Rule]
# HTTP3/QUIC 协议开始流行，但是国内 ISP 和国际出口的 UDP 优先级都很低，表现很差，屏蔽掉以强制回退 HTTP2/HTTP1.1。
# REJECT-NO-DROP 表示不使用默认的自动丢包逻辑，这样 Surge 每次都会返回 ICMP Port Unreachable，应用会立刻回退而不是等超时。
AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP

[MITM]
skip-server-cert-verify = true
hostname = *.amemv.com, *.iydsj.com, *.k.sohu.com, *.kakamobi.cn, *.kingsoft-office-service.com, *.meituan.net, *.musical.ly, *.ofo.com, *.pstatp.com, *.snssdk.com, *.tiktokv.com, *.tv.sohu.com, *.uve.weibo.com, *.ydstatic.com, 101.201.175.228, 119.18.193.135, 123.59.31.1, 154.8.131.171, 182.92.251.113, 4gimg.map.qq.com, a.apicloud.com, a.qiumibao.com, acs.m.taobao.com, act.vip.iqiyi.com, api*.futunn.com, api.21jingji.com, api.caijingmobile.com, api.chelaile.net.cn, api.daydaycook.com.cn, api.douban.com, api.gotokeep.com, api.haohaozhu.cn, api.huomao.com, api.intsig.net, api.izuiyou.com, api.jr.mi.com, api.jxedt.com, api.kkmh.com, api.m.jd.com, api.meipian.me, api.mgzf.com, api.psy-1.com, api.qbb6.com, api.rr.tv, api.smzdm.com, api.vistopia.com.cn, api.waitwaitpay.com, api.wallstreetcn.com, api.weibo.cn, api.xiachufang.com, api.xueqiu.com, api.yangkeduo.com, api.zhihu.com, api.zhuishushenqi.com, api-mifit*.huami.com, api-release.wuta-cam.com, app.58.com, app.api.ke.com, app.bilibili.com, app.mixcapp.com, app.poizon.com, app.variflight.com, app.wy.guahao.com, app.xinpianchang.com, app.yinxiang.com, app.zhuanzhuan.com, appapi.huazhu.com, app-api.smzdm.com, appconf.mail.163.com, appv6.55haitao.com, b.zhuishushenqi.com, business-cdn.shouji.sogou.com, c.m.163.com, cap.caocaokeji.cn, capi.mwee.cn, ccsp-egmas.sf-express.com, cdn.moji.com, cdnfile1.msstatic.com, channel.beitaichufang.com, client.mail.163.com, clientaccess.10086.cn, cms.daydaycook.com.cn, consumer.fcbox.com, creditcardapp.bankcomm.com, daoyu.sdo.com, dl.app.gtja.com, dsa-mfp.fengshows.cn, dxy.com, e.dangdang.com, easyreadfs.nosdn.127.net, g.cdn.pengpengla.com, gateway.shouqiev.com, guide-acs.m.taobao.com, gw.alicdn.com, gw.csdn.net, gw-passenger.01zhuanche.com, heic.alicdn.com, i.ys7.com, iapi.bishijie.com, iface.iqiyi.com, ih2.ireader.com, imeclient.openspeech.cn, img.jiemian.com, img01.10101111cdn.com, interface.music.163.com, ios.lantouzi.com, ios.wps.cn, jump2.bdimg.com, kaola-haitao.oss.kaolacdn.com, learn.chaoxing.com, list-app-m.i4.cn, m*.amap.com, m.client.10010.com, m.ibuscloud.com, m.tuniu.com, m.yap.yahoo.com, manga.bilibili.com, mapi.mafengwo.cn, media.qyer.com, mlife.jf365.boc.cn, mob.mddcloud.com.cn, mobi.360doc.com, mp.weixin.qq.com, mrobot.pcauto.com.cn, mrobot.pconline.com.cn, ms.jr.jd.com, msspjh.emarbox.com, news.ssp.qq.com, newsso.map.qq.com, nnapp.cloudbae.cn, open.qyer.com, p.du.163.com, pan.baidu.com, pic*.chelaile.net, pic1cdn.cmbchina.com, pocketuni.net, portal-xunyou.qingcdn.com, promo.xueqiu.com, pss.txffp.com, r.inews.qq.com, render.alipay.com, res.xiaojukeji.com, resrelease.wuta-cam.com, restapi.iyunmai.com, richmanapi.jxedt.com, rtbapi.douyucdn.cn, s*.zdmimg.com, s.youtube.com, service.4gtv.tv, slapi.oray.net, smkmp.96225.com, snailsleep.net, ss0.bdstatic.com, ssl.kohsocialapp.qq.com, static.vuevideo.net, static1.keepcdn.com, status.boohee.com, support.you.163.com, thor.weidian.com, tieba.baidu.com, tiku.zhan.com, weibointl.api.weibo.cn, www.bodivis.com.cn, www.dandanzan.com, www.flyertea.com, www.hxeduonline.com, www.icourse163.org, www.iyingdi.cn, www.tieba.com, www.youtube.com, www.zhihu.com, www.zybang.com, xyz.cnki.net, xyst.yuanfudao.com, youtubei.googleapis.com, yxyapi*.drcuiyutao.com, zhidao.baidu.com
ca-passphrase = WANWANCLOUD
ca-p12 = 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

{% endif %}
{% if request.target == "quan" %}

[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}
{% if request.target == "quanx" %}

[General]
# --- GENERAL ---
# Wi-Fi Assist
wifi-assist = false

# Latency Benchmark
internet-test-url = http://wifi.vivo.com.cn/generate_204
proxy-test-url = http://cp.cloudflare.com/generate_204
test-timeout = 5

# TLS Engine
tls-provider = openssl

# GeoIP Database
geoip-maxmind-url = https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb
ipv6 = true

# Wi-Fi Access
allow-wifi-access = false
wifi-access-http-port = 6152
wifi-access-socks5-port = 6153

http-listen = 127.0.0.1:6152
socks5-listen = 127.0.0.1:6153

# Remote Controller
external-controller-access = BlankMagic@127.0.0.1:8888

# HTTP API & Web Dashboard
# http-api = X-key@0.0.0.0:6166
//本机浏览器输入127.0.0.1:6166
# http-api-web-dashboard = true

# Compatibility
# > 兼容模式
compatibility-mode = False
# > 跳过代理
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, passenger.t3go.cn, localhost, *.local
# > 排除简单主机名
exclude-simple-hostnames = true

# Experimental
network-framework = false

# DNS Server
dns-server = 223.5.5.5, 114.114.114.114, system
# > 从 /etc/hosts 读取 DNS 记录
read-etc-hosts = true
doh-server = https://dns2.spdio.xyz:3443, https://dns.fiacloud.com:3443/dns-query, https://doh.pub/dns-query, https://dns.alidns.com/dns-query
# > DoH 请求通过代理策略执行
doh-follow-outbound-mode = false

# --- FIREWALL ---
# Routing
include-all-networks = false
include-local-networks = false

# --- ADVANCED ---
# Log Level
loglevel = notify
# 当遇到 REJECT 策略时返回错误页
show-error-page-for-reject = true
# Always Real IP Hosts
always-real-ip = link-ip.nextdns.io, msftconnecttest.com, msftncsi.com, *.msftconnecttest.com, *.msftncsi.com, *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com, *.battlenet.com.cn, *.battlenet.com, *.blzstatic.cn, *.battle.net
# Hijack DNS
hijack-dns = 8.8.8.8:53, 8.8.4.4:53
# TCP Force HTTP Hosts
//KOOWO - 123.59.31.1,119.18.193.135, 122.14.246.33, 175.102.178.52
//TencentVideo - 116.253.24.*, 175.6.26.*, 220.169.153.*
force-http-engine-hosts = *.ott.cibntv.net, 123.59.31.1,119.18.193.135, 122.14.246.33, 175.102.178.52, 116.253.24.*, 175.6.26.*, 220.169.153.*
# VIF Excluded Routes
tun-excluded-routes = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 239.255.255.250/32
# VIF Included Routes
tun-included-routes = 192.168.1.12/32
# 当 Wi-Fi 不是首选网络时 SSID 组策略使用默认策略
use-default-policy-if-wifi-not-primary = false

[Script]
http-request https?:\/\/.*\.iqiyi\.com\/.*authcookie= script-path=https://raw.githubusercontent.com/NobyDa/Script/master/iQIYI-DailyBonus/iQIYI.js

[Host]
# Firebase Cloud Messaging
mtalk.google.com = 108.177.125.188
# Google Dl
dl.google.com = server:119.29.29.29
dl.l.google.com = server:119.29.29.29

[Rule]
# HTTP3/QUIC 协议开始流行，但是国内 ISP 和国际出口的 UDP 优先级都很低，表现很差，屏蔽掉以强制回退 HTTP2/HTTP1.1。
# REJECT-NO-DROP 表示不使用默认的自动丢包逻辑，这样 Surge 每次都会返回 ICMP Port Unreachable，应用会立刻回退而不是等超时。
AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT-NO-DROP

[MITM]
skip-server-cert-verify = true
hostname = *.amemv.com, *.iydsj.com, *.k.sohu.com, *.kakamobi.cn, *.kingsoft-office-service.com, *.meituan.net, *.musical.ly, *.ofo.com, *.pstatp.com, *.snssdk.com, *.tiktokv.com, *.tv.sohu.com, *.uve.weibo.com, *.ydstatic.com, 101.201.175.228, 119.18.193.135, 123.59.31.1, 154.8.131.171, 182.92.251.113, 4gimg.map.qq.com, a.apicloud.com, a.qiumibao.com, acs.m.taobao.com, act.vip.iqiyi.com, api*.futunn.com, api.21jingji.com, api.caijingmobile.com, api.chelaile.net.cn, api.daydaycook.com.cn, api.douban.com, api.gotokeep.com, api.haohaozhu.cn, api.huomao.com, api.intsig.net, api.izuiyou.com, api.jr.mi.com, api.jxedt.com, api.kkmh.com, api.m.jd.com, api.meipian.me, api.mgzf.com, api.psy-1.com, api.qbb6.com, api.rr.tv, api.smzdm.com, api.vistopia.com.cn, api.waitwaitpay.com, api.wallstreetcn.com, api.weibo.cn, api.xiachufang.com, api.xueqiu.com, api.yangkeduo.com, api.zhihu.com, api.zhuishushenqi.com, api-mifit*.huami.com, api-release.wuta-cam.com, app.58.com, app.api.ke.com, app.bilibili.com, app.mixcapp.com, app.poizon.com, app.variflight.com, app.wy.guahao.com, app.xinpianchang.com, app.yinxiang.com, app.zhuanzhuan.com, appapi.huazhu.com, app-api.smzdm.com, appconf.mail.163.com, appv6.55haitao.com, b.zhuishushenqi.com, business-cdn.shouji.sogou.com, c.m.163.com, cap.caocaokeji.cn, capi.mwee.cn, ccsp-egmas.sf-express.com, cdn.moji.com, cdnfile1.msstatic.com, channel.beitaichufang.com, client.mail.163.com, clientaccess.10086.cn, cms.daydaycook.com.cn, consumer.fcbox.com, creditcardapp.bankcomm.com, daoyu.sdo.com, dl.app.gtja.com, dsa-mfp.fengshows.cn, dxy.com, e.dangdang.com, easyreadfs.nosdn.127.net, g.cdn.pengpengla.com, gateway.shouqiev.com, guide-acs.m.taobao.com, gw.alicdn.com, gw.csdn.net, gw-passenger.01zhuanche.com, heic.alicdn.com, i.ys7.com, iapi.bishijie.com, iface.iqiyi.com, ih2.ireader.com, imeclient.openspeech.cn, img.jiemian.com, img01.10101111cdn.com, interface.music.163.com, ios.lantouzi.com, ios.wps.cn, jump2.bdimg.com, kaola-haitao.oss.kaolacdn.com, learn.chaoxing.com, list-app-m.i4.cn, m*.amap.com, m.client.10010.com, m.ibuscloud.com, m.tuniu.com, m.yap.yahoo.com, manga.bilibili.com, mapi.mafengwo.cn, media.qyer.com, mlife.jf365.boc.cn, mob.mddcloud.com.cn, mobi.360doc.com, mp.weixin.qq.com, mrobot.pcauto.com.cn, mrobot.pconline.com.cn, ms.jr.jd.com, msspjh.emarbox.com, news.ssp.qq.com, newsso.map.qq.com, nnapp.cloudbae.cn, open.qyer.com, p.du.163.com, pan.baidu.com, pic*.chelaile.net, pic1cdn.cmbchina.com, pocketuni.net, portal-xunyou.qingcdn.com, promo.xueqiu.com, pss.txffp.com, r.inews.qq.com, render.alipay.com, res.xiaojukeji.com, resrelease.wuta-cam.com, restapi.iyunmai.com, richmanapi.jxedt.com, rtbapi.douyucdn.cn, s*.zdmimg.com, s.youtube.com, service.4gtv.tv, slapi.oray.net, smkmp.96225.com, snailsleep.net, ss0.bdstatic.com, ssl.kohsocialapp.qq.com, static.vuevideo.net, static1.keepcdn.com, status.boohee.com, support.you.163.com, thor.weidian.com, tieba.baidu.com, tiku.zhan.com, weibointl.api.weibo.cn, www.bodivis.com.cn, www.dandanzan.com, www.flyertea.com, www.hxeduonline.com, www.icourse163.org, www.iyingdi.cn, www.tieba.com, www.youtube.com, www.zhihu.com, www.zybang.com, xyz.cnki.net, xyst.yuanfudao.com, youtubei.googleapis.com, yxyapi*.drcuiyutao.com, zhidao.baidu.com
ca-passphrase = WANWANCLOUD
ca-p12 = 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

{% endif %}
{% if request.target == "mellow" %}

[Endpoint]
DIRECT, builtin, freedom, domainStrategy=UseIP
REJECT, builtin, blackhole
Dns-Out, builtin, dns

[Routing]
domainStrategy = IPIfNonMatch

[Dns]
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
localhost
223.5.5.5
8.8.8.8, 53, Remote
8.8.4.4

[DnsRule]
DOMAIN-KEYWORD, geosite:geolocation-!cn, Remote
DOMAIN-SUFFIX, google.com, Remote

[DnsHost]
doubleclick.net = 127.0.0.1

[Log]
loglevel = warning

{% endif %}
{% if request.target == "surfboard" %}

[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
{% if request.target == "sssub" %}
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "ipv6": false,
  "metered": false,
  "proxy_apps": {
    "enabled": false,
    "bypass": true,
    "android_list": [
      "com.eg.android.AlipayGphone",
      "com.wudaokou.hippo",
      "com.zhihu.android"
    ]
  },
  "udpdns": false
}

{% endif %}
