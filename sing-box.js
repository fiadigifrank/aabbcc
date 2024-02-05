const { type, name } = $arguments
const compatible_outbound = {
    tag: 'COMPATIBLE',
    type: 'direct',
}

let compatible
let config = JSON.parse($files[0])
let proxies = await produceArtifact({
    name,
    type: /^1$|col/i.test(type) ? 'collection' : 'subscription',
    platform: 'sing-box',
    produceType: 'internal',
})

config.outbounds.push(...proxies)

config.outbounds.map(i => {
    if (['🕹️ All', '🕹️ All-auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies))
    }
    if (['🦹 Hy2', '🦹 Hy2-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /Hy|Hy2|Hysteria|Hysteria2|🦹/i))
    }
    if (['🇰🇷 KR', '🇰🇷 KR-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /韩|kr|KR|Korea|KOR|🇰🇷|首尔|韩|韓|春川/i))
    }
    if (['🇭🇰 HK', '🇭🇰 HK-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /港|hk|hongkong|kong kong|🇭🇰/i))
    }
    if (['🇹🇼 TW', '🇹🇼 TW-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /台|tw|TW|taiwan|🇹🇼/i))
    }
    if (['🇯🇵 JP', '🇯🇵 JP-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /日本|jp|JP|japan|🇯🇵/i))
    }
    if (['🇸🇬 SG', '🇸🇬 SG-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /^(?!.*(?:us)).*(新|sg|singapore|🇸🇬)/i))
    }
    if (['🇺🇲 US', '🇺🇲 US-Auto'].includes(i.tag)) {
        i.outbounds.push(...getTags(proxies, /美|us|unitedstates|united states|🇺🇸/i))
    }
})

config.outbounds.forEach(outbound => {
    if (Array.isArray(outbound.outbounds) && outbound.outbounds.length === 0) {
    if (!compatible) {
        config.outbounds.push(compatible_outbound)
        compatible = true
    }
    outbound.outbounds.push(compatible_outbound.tag);
    }
});

$content = JSON.stringify(config, null, 2)

function getTags(proxies, regex) {
    return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}