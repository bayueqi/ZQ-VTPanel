import { connect } from "cloudflare:sockets";

function trojanpwd(s) {
    const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const r = (n,b) => ((n>>>b)|(n<<(32-b)))>>>0;
    s = unescape(encodeURIComponent(s));
    const l = s.length*8;
    s += String.fromCharCode(0x80);
    while((s.length*8)%512!==448) s += String.fromCharCode(0);
    const h = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
    const hi=Math.floor(l/0x100000000),lo=l&0xffffffff;
    s += String.fromCharCode((hi>>>24)&0xff,(hi>>>16)&0xff,(hi>>>8)&0xff,hi&0xff,(lo>>>24)&0xff,(lo>>>16)&0xff,(lo>>>8)&0xff,lo&0xff);
    const w=[];
    for(let i=0;i<s.length;i+=4) w.push((s.charCodeAt(i)<<24)|(s.charCodeAt(i+1)<<16)|(s.charCodeAt(i+2)<<8)|s.charCodeAt(i+3));
    for(let i=0;i<w.length;i+=16){
        const x=new Array(64).fill(0);
        for(let j=0;j<16;j++) x[j]=w[i+j];
        for(let j=16;j<64;j++){
            const s0=r(x[j-15],7)^r(x[j-15],18)^(x[j-15]>>>3);
            const s1=r(x[j-2],17)^r(x[j-2],19)^(x[j-2]>>>10);
            x[j]=(x[j-16]+s0+x[j-7]+s1)>>>0;
        }
        let [a,b,c,d,e,f,g,h0]=h;
        for(let j=0;j<64;j++){
            const S1=r(e,6)^r(e,11)^r(e,25);
            const ch=(e&f)^(~e&g);
            const t1=(h0+S1+ch+K[j]+x[j])>>>0;
            const S0=r(a,2)^r(a,13)^r(a,22);
            const maj=(a&b)^(a&c)^(b&c);
            const t2=(S0+maj)>>>0;
            h0=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
        }
        for(let j=0;j<8;j++) h[j]=(h[j]+[a,b,c,d,e,f,g,h0][j])>>>0;
    }
    let hex="";
    for(let i=0;i<7;i++) for(let j=24;j>=0;j-=8) hex += ((h[i]>>>j)&0xff).toString(16).padStart(2,"0");
    return hex;
}

function parseTrojanRequest(buffer,pwd){
    const p=trojanpwd(pwd);
    if(buffer.byteLength<56) return {hasError:true,message:"invalid data"};
    const b=new Uint8Array(buffer);
    if(b[56]!==0x0d||b[57]!==0x0a) return {hasError:true,message:"invalid header"};
    if(new TextDecoder().decode(buffer.slice(0,56))!==p) return {hasError:true,message:"invalid password"};
    const s5buf=buffer.slice(58);
    if(s5buf.byteLength<6) return {hasError:true,message:"invalid S5 data"};
    const v=new DataView(s5buf);
    const cmd=v.getUint8(0);
    if(cmd!==1&&cmd!==3) return {hasError:true,message:"unsupported cmd"};
    const at=v.getUint8(1);
    const isUDP=cmd===3;
    let addr="",ai=2,al=0;
    if(at===1){
        al=4;
        addr=new Uint8Array(s5buf.slice(ai,ai+al)).join(".");
    }else if(at===3){
        al=v.getUint8(ai);
        ai++;
        addr=new TextDecoder().decode(s5buf.slice(ai,ai+al));
    }else if(at===4){
        al=16;
        const dv=new DataView(s5buf.slice(ai,ai+al));
        const ip6=[];
        for(let i=0;i<8;i++) ip6.push(dv.getUint16(i*2).toString(16));
        addr=ip6.join(":");
    }else return {hasError:true,message:"invalid atype"};
    if(!addr) return {hasError:true,message:"empty addr"};
    const pi=ai+al,port=v.getUint16(pi);
    return {hasError:false,addressType:at,port:port,hostname:addr,isUDP:isUDP,rawClientData:s5buf.slice(pi+4)};
}

const text=(c,s=200)=>new Response(c,{status:s,headers:{"content-type":"text/plain; charset=utf-8"}});
const json=(c,s=200)=>new Response(JSON.stringify(c),{status:s,headers:{"content-type":"application/json; charset=utf-8"}});
const b64e=(s)=>{const e=new TextEncoder(),b=e.encode(s);return btoa(String.fromCharCode(...new Uint8Array(b)));};
const randStr=()=>Math.random().toString(36).slice(2,8);
const paths=["/static/js","/assets/img","/api/2024","/cdn/file","/upload/data","/media/v2","/lib/ext","/res/now","/stat/click","/track/log","/api/v1/data","/css/main","/js/app","/fonts/google","/images/hero","/videos/intro","/api/v2/user","/assets/css","/static/media","/build/js","/dist/css","/public/img","/content/data","/files/doc","/download/pkg","/api/v3/item","/resource/img"];
const paramsMap={t:["m","type","mode"],d:["dir","direct","d"],s:["socks","proxy","s"],p:["ip","proxyip","p"],v:["r","rand","v","id","t"]};
const getPath=()=>paths[Math.floor(Math.random()*paths.length)];
const getParam=(key)=>paramsMap[key][Math.floor(Math.random()*paramsMap[key].length)];

// ----------- 共享常量和工具 -----------
const DEFAULT_UUID = "ef9d104e-ca0e-4202-ba4b-a0afb969c747";
const DEFAULT_BEST_IP_API = "https://ipdb.api.030101.xyz/?type=bestcf";
const DEFAULT_ECH_SNI = "cloudflare-ech.com";
const DEFAULT_ECH_DNS = "https://sm2.doh.pub/dns-query";
// 订阅转换服务（Sublink Worker）。可用环境变量 SUBLINK_BASE 覆盖，换成你自己部署的 Sublink。
const DEFAULT_SUBLINK_BASE = "https://sublink.vpnjacky.dpdns.org";
// Sublink 原生 API 是 /clash /singbox /surge /xray?config=...，
// 并没有 subconverter 那种 /sub?target=... 接口，所以这里只做「目标 -> 端点」白名单映射。
const SUBLINK_TARGET_ENDPOINTS = { clash: "clash", singbox: "singbox", surge: "surge" };
// 订阅转换服务地址归一化：只接受 http(s):// 的服务根地址，去掉尾部斜杠。
// 带 ? 或 # 说明用户贴的是完整订阅/转换链接而不是服务地址，一律判为非法并返回 ""（由调用方回退默认值）
function normalizeSubLinkBase(v) {
    if (typeof v !== "string") return "";
    const s = v.trim().replace(/\/+$/, "");
    if (/[?#]/.test(s)) return "";
    return /^https?:\/\/[^\s/]+/i.test(s) ? s : "";
}
const DEFAULT_CONFIG = {
    uuid: DEFAULT_UUID, domain: "", port: "443", s5: "", proxyIp: "",
    domains: [], ports: [443], fallbackTimeout: 100,
    subLinkBase: DEFAULT_SUBLINK_BASE,
    bestIpApi: DEFAULT_BEST_IP_API, autoUpdateBestIp: false,
    nodeTypes: ["direct"], protocols: ["vless", "trojan"],
    ech: false, echConfig: { sni: DEFAULT_ECH_SNI, dns: DEFAULT_ECH_DNS },
};

// 根据 userConfig 生成 ECH 链接参数；未启用时返回空串
function buildEchParam(userConfig) {
    if (!userConfig?.ech || !userConfig?.echConfig) return "";
    const sni = userConfig.echConfig.sni || "";
    const dns = userConfig.echConfig.dns || "";
    const payload = (sni ? sni + "+" : "") + dns;
    if (!payload) return "";
    return `&ech=${encodeURIComponent(payload)}`;
}

// ---- ECH 订阅热补丁（让被墙域名也能通过 ECH 加密 SNI 翻墙）----
// 思路：subapi 转换会丢失 ECH 信息，因此在返回前对 clash / singbox 内容做热补丁。
//  - Clash: 给节点加 ech-opts，并在 dns 下加 nameserver-policy，将所有节点域名走 ECH DoH 解析
//  - Singbox: 给匹配 UUID 的 outbound 加 tls.ech 配置

const CLASH_BASE_DNS = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

function clashEchHotPatch(clashYaml, { uuid, echSni, echDns, hosts }) {
    if (!uuid) return clashYaml;
    const echEnabled = Boolean(echSni || echDns);
    const hostList = Array.isArray(hosts) ? [...hosts] : [];
    if (echSni && !hostList.includes(echSni)) hostList.push(echSni);
    let yaml = clashYaml.replace(/mode:\s*Rule\b/g, "mode: rule");

    // 1. 确保存在 dns 块
    if (!/^dns:\s*(?:\n|$)/m.test(yaml)) yaml = CLASH_BASE_DNS + yaml;

    // 2. 插入 nameserver-policy，让所有节点域名走 ECH DoH 解析（绕过 DNS 污染）
    if (echEnabled && hostList.length > 0 && echDns) {
        const hostsEntries = hostList.map((h) => `    "${h}": ${echDns}`).join("\n");
        if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
            yaml = yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
        } else {
            const lines = yaml.split("\n");
            let dnsEnd = -1;
            let inDns = false;
            for (let i = 0; i < lines.length; i++) {
                if (/^dns:\s*$/.test(lines[i])) { inDns = true; continue; }
                if (inDns && /^[a-zA-Z]/.test(lines[i])) { dnsEnd = i; break; }
            }
            const block = `  nameserver-policy:\n${hostsEntries}`;
            if (dnsEnd !== -1) lines.splice(dnsEnd, 0, block);
            else lines.push(block);
            yaml = lines.join("\n");
        }
    }

    if (!echEnabled) return yaml;

    // 3. 遍历节点，给匹配 UUID 的节点加 ech-opts
    const getProxyType = (t) => t.match(/type:\s*(\w+)/)?.[1] || "vless";
    const getCredential = (t, isFlow) => {
        const field = getProxyType(t) === "trojan" ? "password" : "uuid";
        const re = new RegExp(`${field}:\\s*${isFlow ? "([^,}\\n]+)" : "([^\\n]+)"}`);
        return t.match(re)?.[1]?.trim() || null;
    };
    const addBlockEchOpts = (nodeLines, topIndent) => {
        let insertIdx = -1;
        for (let j = nodeLines.length - 1; j >= 0; j--) {
            if (nodeLines[j].trim()) { insertIdx = j; break; }
        }
        if (insertIdx < 0) return nodeLines;
        const indent = " ".repeat(topIndent);
        const lines = [`${indent}ech-opts:`, `${indent}  enable: true`];
        if (echSni) lines.push(`${indent}  query-server-name: ${echSni}`);
        nodeLines.splice(insertIdx + 1, 0, ...lines);
        return nodeLines;
    };

    const lines = yaml.split("\n");
    const out = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith("- {")) {
            // 流式单行/多行节点
            let full = line;
            let brace = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
            while (brace > 0 && i + 1 < lines.length) {
                i++;
                full += "\n" + lines[i];
                brace += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
            }
            if (getCredential(full, true) === uuid.trim()) {
                full = full.replace(/\}(\s*)$/, `, ech-opts: {enable: true${echSni ? `, query-server-name: ${echSni}` : ""}}}$1`);
            }
            out.push(full);
            i++;
        } else if (trimmed.startsWith("- name:")) {
            // 块式节点
            const nodeLines = [line];
            const baseIndent = line.search(/\S/);
            const topIndent = baseIndent + 2;
            i++;
            while (i < lines.length) {
                const next = lines[i];
                const nt = next.trim();
                if (!nt) { nodeLines.push(next); i++; break; }
                const ni = next.search(/\S/);
                if (ni <= baseIndent && nt.startsWith("- ")) break;
                if (ni < baseIndent && nt) break;
                nodeLines.push(next);
                i++;
            }
            const nodeText = nodeLines.join("\n");
            if (getCredential(nodeText, false) === uuid.trim()) {
                addBlockEchOpts(nodeLines, topIndent);
            }
            out.push(...nodeLines);
        } else {
            out.push(line);
            i++;
        }
    }
    return out.join("\n");
}

function singboxEchHotPatch(singboxText, { uuid, echSni }) {
    if (!uuid) return singboxText;
    const echEnabled = Boolean(echSni);
    if (!echEnabled) return singboxText;
    try {
        const config = JSON.parse(singboxText.replace("1.1.1.1", "8.8.8.8").replace("1.0.0.1", "8.8.4.4"));
        if (Array.isArray(config.outbounds)) {
            config.outbounds.forEach((outbound) => {
                if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
                    if (!outbound.tls) outbound.tls = { enabled: true };
                    outbound.tls.ech = {
                        enabled: true,
                        query_server_name: echSni,
                    };
                }
            });
        }
        return JSON.stringify(config, null, 2);
    } catch (e) {
        console.error("Singbox ECH 热补丁失败:", e);
        return singboxText;
    }
}
const SESSION_COOKIE_RE = /(?:^|;\s*)session=([^;]+)/;
const SESSION_COOKIE = (uuid) => `session=${uuid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;

// 从 cookie 或 URL query 里取 session UUID，都没有返回 null
function getSessionUUID(req, url) {
    if (url) {
        const p = url.searchParams.get("pwd") || url.searchParams.get("uuid");
        if (p) return p;
    }
    const m = (req.headers.get("cookie") || "").match(SESSION_COOKIE_RE);
    return m ? m[1] : null;
}

async function getUserConfig(env) {
    const fallback = { ...DEFAULT_CONFIG };
    // SUBLINK_BASE 环境变量作为「部署级默认值」：存储里没有 subLinkBase 时（老配置）生效。
    // 面板上保存过一次之后就以北面板里的值为准。
    const envBase = normalizeSubLinkBase(env?.SUBLINK_BASE);
    if (envBase) fallback.subLinkBase = envBase;
    try {
        const cfg = await env.VTPanel?.get("user_config", "json");
        const m = cfg || {};
        // 兼容旧格式：字符串数组 → 对象数组
        if (Array.isArray(m.domains)) {
            m.domains = m.domains.map((x) =>
                typeof x === "string" ? { ip: x, remark: "" } : x,
            ).filter((x) => x && x.ip);
        } else {
            m.domains = [];
        }
        m.ports = Array.isArray(m.ports) ? m.ports : [];
        m.fallbackTimeout =
            typeof m.fallbackTimeout === "number"
                ? Math.max(1, Math.min(5000, m.fallbackTimeout)) : 100;
        m.bestIpApi = m.bestIpApi || DEFAULT_BEST_IP_API;
        m.subLinkBase = normalizeSubLinkBase(m.subLinkBase) || fallback.subLinkBase;
        m.autoUpdateBestIp = !!m.autoUpdateBestIp;
        if (!Array.isArray(m.nodeTypes) || !m.nodeTypes.length) m.nodeTypes = ["direct"];
        if (!Array.isArray(m.protocols) || !m.protocols.length) m.protocols = ["vless", "trojan"];
        // ECH 字段归一化（兼容旧配置）
        m.ech = !!m.ech;
        if (!m.echConfig || typeof m.echConfig !== "object" || Array.isArray(m.echConfig)) m.echConfig = {};
        let echSni = typeof m.echConfig.sni === "string" ? m.echConfig.sni.trim() : "";
        let echDns = typeof m.echConfig.dns === "string" ? m.echConfig.dns.trim() : "";
        m.echConfig.sni = echSni || DEFAULT_ECH_SNI;
        m.echConfig.dns = echDns || DEFAULT_ECH_DNS;
        const d = (m.domain || "").trim();
        if (d && !m.domains.some((x) => x.ip === d)) m.domains.unshift({ ip: d, remark: "" });
        const pn = Math.max(1, Math.min(65535, parseInt(m.port || "443", 10) || 443));
        if (!m.ports.some((x) => +x === pn)) m.ports.push(pn);
        return { ...fallback, ...m };
    } catch {
        return fallback;
    }
}

// ===================== 其它代理（socks5 / http / https / sstp / turn） =====================
// 面板「其它代理」一栏填带协议前缀的完整地址，不带前缀按 SOCKS5 处理（兼容旧配置）：
//   host:port / user:pass@host:port   → SOCKS5
//   socks5://user:pass@host:port      → SOCKS5
//   http://user:pass@host:port        → HTTP CONNECT 隧道
//   https://user:pass@host:port       → HTTPS(TLS) CONNECT 隧道
//   sstp://user:pass@host:port        → SSTP（VPN Gate 那类只出隧道协议的家宽节点走这个）
//   turn://user:pass@host:port        → TURN 中继（RFC 6062）
const PROXY_DEFAULT_PORTS={socks5:1080,http:80,https:443,sstp:443,turn:3478};
const PROXY_BASE64_CREDENTIAL=/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const PROXY_CONNECT_TIMEOUT_MS=9999;
const textEncoder=new TextEncoder();
const textDecoder=new TextDecoder();
const EMPTY_BYTES=new Uint8Array(0);
const SSTP_TCP_MSS=1400;

function stripIPv6Brackets(host){const value=String(host||"").trim();return value.startsWith("[")&&value.endsWith("]")?value.slice(1,-1):value;}
function isIPv4(value){const parts=String(value||"").split(".");return parts.length===4&&parts.every((part)=>/^\d{1,3}$/.test(part)&&Number(part)<=255);}
function toUint8(data){
    if(data instanceof Uint8Array) return data;
    if(data instanceof ArrayBuffer) return new Uint8Array(data);
    if(ArrayBuffer.isView(data)) return new Uint8Array(data.buffer,data.byteOffset,data.byteLength);
    return new Uint8Array(data||0);
}
function concatBytes(...chunks){
    if(!chunks||!chunks.length) return new Uint8Array(0);
    const list=chunks.map(toUint8);
    const total=list.reduce((sum,chunk)=>sum+chunk.byteLength,0);
    const merged=new Uint8Array(total);
    let offset=0;
    for(const chunk of list){merged.set(chunk,offset);offset+=chunk.byteLength;}
    return merged;
}
function withTimeout(promise,timeoutMs,message){
    let timer;
    return Promise.race([
        promise,
        new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(message)),timeoutMs);}),
    ]).finally(()=>clearTimeout(timer));
}
function readUint16(bytes,offset=0){return (bytes[offset]<<8)|bytes[offset+1];}
function readUint32(bytes,offset=0){return ((bytes[offset]<<24)|(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3])>>>0;}
function randomUint16(){return readUint16(crypto.getRandomValues(new Uint8Array(2)));}
function internetChecksum(bytes,offset,length){
    let sum=0;
    for(let i=offset;i<offset+length-1;i+=2) sum+=readUint16(bytes,i);
    if(length&1) sum+=bytes[offset+length-1]<<8;
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (~sum)&0xffff;
}
// SSTP / TURN 都要自己拼 IP 包，必须先拿到目标的 A 记录
async function resolveIPv4(host){
    const target=stripIPv6Brackets(host);
    if(isIPv4(target)) return target;
    try{
        const res=await fetch("https://1.1.1.1/dns-query?name="+encodeURIComponent(target)+"&type=A",{headers:{accept:"application/dns-json"}});
        const data=await res.json();
        const record=(data.Answer||[]).find((item)=>item.type===1&&isIPv4(item.data));
        return record?record.data:null;
    }catch(e){
        return null;
    }
}

// 把其它代理地址解析成 { type, host, port, username, password }
function parseProxyAddress(proxyStr){
    if(!proxyStr) return null;
    const raw=String(proxyStr).trim().split("#")[0].trim();
    if(!raw) return null;
    const matched=/^(socks5|socks|http|https|sstp|turn):\/\//i.exec(raw);
    let type="socks5",rest=raw;
    if(matched){
        type=matched[1].toLowerCase();
        rest=raw.slice(matched[0].length);
    }
    if(type==="socks") type="socks5";
    const at=rest.lastIndexOf("@");
    const credential=at===-1?"":rest.slice(0,at);
    const server=(at===-1?rest:rest.slice(at+1)).split("/")[0];
    let username="",password="";
    if(credential){
        // 兼容订阅里常见的 base64(user:pass) 写法
        let decoded=credential.replaceAll("%3D","=");
        if(!decoded.includes(":")&&PROXY_BASE64_CREDENTIAL.test(decoded)){
            try{decoded=atob(decoded);}catch(e){}
        }
        const split=decoded.indexOf(":");
        if(split===-1) return null;
        try{
            username=decodeURIComponent(decoded.slice(0,split));
            password=decodeURIComponent(decoded.slice(split+1));
        }catch(e){
            username=decoded.slice(0,split);
            password=decoded.slice(split+1);
        }
    }
    let host=server,port=PROXY_DEFAULT_PORTS[type]||0,hasExplicitPort=false;
    if(server.startsWith("[")){
        const close=server.indexOf("]");
        if(close===-1) return null;
        host=server.slice(0,close+1);
        const tail=server.slice(close+1);
        if(tail.startsWith(":")){
            port=parseInt(tail.slice(1),10);
            hasExplicitPort=true;
        }
    }else if(server.includes(":")){
        const parts=server.split(":");
        if(parts.length!==2) return null;
        host=parts[0];
        port=parseInt(parts[1],10);
        hasExplicitPort=true;
    }
    // 没写协议前缀时必须显式带端口：避免把随手输入的字符串当成代理地址（保持旧版行为）
    if(!matched&&!hasExplicitPort) return null;
    if(!host||!Number.isFinite(port)||port<=0||port>65535) return null;
    return {type,host,port,username,password};
}

function proxyTypeLabel(address){
    const config=parseProxyAddress(address);
    if(!config) return "SOCKS5";
    return ({socks5:"SOCKS5",http:"HTTP",https:"HTTPS",sstp:"SSTP",turn:"TURN"})[config.type]||config.type.toUpperCase();
}

async function socks5Connect(socket,proxyConfig,targetHost,targetPort,timeoutMs){
    const writer=socket.writable.getWriter(),reader=socket.readable.getReader();
    try{
        const authMethods=proxyConfig.username&&proxyConfig.password?new Uint8Array([0x05,0x02,0x00,0x02]):new Uint8Array([0x05,0x01,0x00]);
        await writer.write(authMethods);
        let res=await Promise.race([reader.read(),new Promise((r)=>setTimeout(()=>r({timeout:true}),timeoutMs))]);
        if(!res||res.timeout) throw new Error("SOCKS5 timeout");
        const method=new Uint8Array(res.value)[1];
        if(method===0x02){
            if(!proxyConfig.username||!proxyConfig.password) throw new Error("SOCKS5 auth required");
            const uBytes=new TextEncoder().encode(proxyConfig.username),pBytes=new TextEncoder().encode(proxyConfig.password);
            const auth=new Uint8Array(3+uBytes.length+pBytes.length);
            auth[0]=0x01;auth[1]=uBytes.length;auth.set(uBytes,2);auth[2+uBytes.length]=pBytes.length;auth.set(pBytes,3+uBytes.length);
            await writer.write(auth);
            res=await Promise.race([reader.read(),new Promise((r)=>setTimeout(()=>r({timeout:true}),timeoutMs))]);
            if(!res||res.timeout||new Uint8Array(res.value)[1]!==0x00) throw new Error("SOCKS5 auth failed");
        }else if(method!==0x00) throw new Error(`SOCKS5 unsupported method: ${method}`);
        const hostBytes=new TextEncoder().encode(targetHost);
        const connect=new Uint8Array(7+hostBytes.length);
        connect[0]=0x05;connect[1]=0x01;connect[2]=0x00;connect[3]=0x03;connect[4]=hostBytes.length;
        connect.set(hostBytes,5);new DataView(connect.buffer).setUint16(5+hostBytes.length,targetPort,false);
        await writer.write(connect);
        res=await Promise.race([reader.read(),new Promise((r)=>setTimeout(()=>r({timeout:true}),timeoutMs))]);
        if(!res||res.timeout||new Uint8Array(res.value)[1]!==0x00) throw new Error("SOCKS5 connect failed");
        return {writer,reader};
    }catch(e){writer.releaseLock();reader.releaseLock();throw e;}
}

// ---- HTTP / HTTPS 代理（CONNECT 隧道）----
async function httpConnect(proxyConfig,targetHost,targetPort,useTLS=false){
    const serverHost=stripIPv6Brackets(proxyConfig.host);
    const socket=useTLS
        ? connect({hostname:serverHost,port:proxyConfig.port},{secureTransport:"on",allowHalfOpen:false})
        : connect({hostname:serverHost,port:proxyConfig.port});
    const writer=socket.writable.getWriter(),reader=socket.readable.getReader();
    try{
        if(useTLS) await withTimeout(socket.opened,PROXY_CONNECT_TIMEOUT_MS,"HTTPS proxy connection timeout");
        const auth=proxyConfig.username&&proxyConfig.password
            ?`Proxy-Authorization: Basic ${btoa(proxyConfig.username+":"+proxyConfig.password)}\r\n`
            :"";
        const target=`${stripIPv6Brackets(targetHost)}:${targetPort}`;
        const request=`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(textEncoder.encode(request));
        writer.releaseLock();

        let head=new Uint8Array(0),headEnd=-1,readBytes=0;
        while(headEnd===-1&&readBytes<8192){
            const {done,value}=await reader.read();
            if(done||!value) throw new Error((useTLS?"HTTPS":"HTTP")+" proxy closed before CONNECT response");
            head=new Uint8Array([...head,...value]);
            readBytes=head.length;
            const index=head.findIndex((_,i)=>i<head.length-3&&head[i]===0x0d&&head[i+1]===0x0a&&head[i+2]===0x0d&&head[i+3]===0x0a);
            if(index!==-1) headEnd=index+4;
        }
        if(headEnd===-1) throw new Error("Proxy CONNECT response header too long or invalid");
        const statusMatch=textDecoder.decode(head.slice(0,headEnd)).split("\r\n")[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode=statusMatch?parseInt(statusMatch[1],10):NaN;
        if(!Number.isFinite(statusCode)||statusCode<200||statusCode>=300) throw new Error("Proxy refused connection: HTTP "+statusCode);
        reader.releaseLock();

        if(readBytes>headEnd){
            const {readable,writable}=new TransformStream();
            const bridgeWriter=writable.getWriter();
            await bridgeWriter.write(head.subarray(headEnd,readBytes));
            bridgeWriter.releaseLock();
            socket.readable.pipeTo(writable).catch(()=>{});
            return {readable,writable:socket.writable,closed:socket.closed,close:()=>socket.close()};
        }
        return socket;
    }catch(error){
        try{writer.releaseLock();}catch(e){}
        try{reader.releaseLock();}catch(e){}
        try{socket.close();}catch(e){}
        throw error;
    }
}

// ---- HTTPS 代理：自研 TLS 客户端（不校验证书，AES-GCM / ChaCha20-Poly1305 双套件，TLS 1.2 / 1.3）----
// 不用 CF 内置的 secureTransport:"on"：它会校验证书，公共 HTTPS 代理多为自签 → 握手必失败；且只提供 AES-GCM 套件。
function isIpAddress(hostname=""){
    const host=stripIPv6Brackets(hostname);
    const ipv4Regex=/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    if(ipv4Regex.test(host)) return true;
    if(!host.includes(":")) return false;
    try{
        new URL(`http://[${host}]/`);
        return true;
    }catch(e){
        return false;
    }
}

const TLS_VERSION_10=769,TLS_VERSION_12=771,TLS_VERSION_13=772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC=20,CONTENT_TYPE_ALERT=21,CONTENT_TYPE_HANDSHAKE=22,CONTENT_TYPE_APPLICATION_DATA=23;
const HANDSHAKE_TYPE_CLIENT_HELLO=1,HANDSHAKE_TYPE_SERVER_HELLO=2,HANDSHAKE_TYPE_NEW_SESSION_TICKET=4,HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS=8,HANDSHAKE_TYPE_CERTIFICATE=11,HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE=12,HANDSHAKE_TYPE_CERTIFICATE_REQUEST=13,HANDSHAKE_TYPE_SERVER_HELLO_DONE=14,HANDSHAKE_TYPE_CERTIFICATE_VERIFY=15,HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE=16,HANDSHAKE_TYPE_FINISHED=20,HANDSHAKE_TYPE_KEY_UPDATE=24;
const EXT_SERVER_NAME=0,EXT_SUPPORTED_GROUPS=10,EXT_EC_POINT_FORMATS=11,EXT_SIGNATURE_ALGORITHMS=13,EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION=16,EXT_SUPPORTED_VERSIONS=43,EXT_PSK_KEY_EXCHANGE_MODES=45,EXT_KEY_SHARE=51;

const ALERT_CLOSE_NOTIFY=0,ALERT_LEVEL_WARNING=1,ALERT_UNRECOGNIZED_NAME=112;
const shouldIgnoreTlsAlert=(fragment)=>fragment?.[0]===ALERT_LEVEL_WARNING&&fragment?.[1]===ALERT_UNRECOGNIZED_NAME;

const CIPHER_SUITES_BY_ID=new Map([
    [4865,{id:4865,keyLen:16,ivLen:12,hash:"SHA-256",tls13:!0}],
    [4866,{id:4866,keyLen:32,ivLen:12,hash:"SHA-384",tls13:!0}],
    [4867,{id:4867,keyLen:32,ivLen:12,hash:"SHA-256",tls13:!0,chacha:!0}],
    [49199,{id:49199,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"}],
    [49200,{id:49200,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"}],
    [52392,{id:52392,keyLen:32,ivLen:12,hash:"SHA-256",kex:"ECDHE",chacha:!0}],
    [49195,{id:49195,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"}],
    [49196,{id:49196,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"}],
    [52393,{id:52393,keyLen:32,ivLen:12,hash:"SHA-256",kex:"ECDHE",chacha:!0}]
]);
const GROUPS_BY_ID=new Map([[29,"X25519"],[23,"P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS=[2052,2053,2054,1025,1281,1537,1027,1283,1539];

const tlsBytes=(...parts)=>{
    const flattenBytes=(values)=>values.flatMap((value)=>value instanceof Uint8Array?[...value]:Array.isArray(value)?flattenBytes(value):"number"==typeof value?[value]:[]);
    return new Uint8Array(flattenBytes(parts));
};
const uint16be=(value)=>[value>>8&255,255&value];
const readUint24=(buffer,offset)=>buffer[offset]<<16|buffer[offset+1]<<8|buffer[offset+2];
const randomBytes=(length)=>crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual=(left,right)=>{
    if(!left||!right||left.length!==right.length) return !1;
    let diff=0;
    for(let index=0;index<left.length;index++) diff|=left[index]^right[index];
    return 0===diff;
};
const hashByteLength=(hash)=>"SHA-512"===hash?64:"SHA-384"===hash?48:32;
async function hmac(hash,key,data){
    const cryptoKey=await crypto.subtle.importKey("raw",key,{name:"HMAC",hash},!1,["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC",cryptoKey,data));
}
async function digestBytes(hash,data){return new Uint8Array(await crypto.subtle.digest(hash,data));}
async function tls12Prf(secret,label,seed,length,hash="SHA-256"){
    const labelSeed=concatBytes(textEncoder.encode(label),seed);
    let output=new Uint8Array(0),currentA=labelSeed;
    for(;output.length<length;){
        currentA=await hmac(hash,secret,currentA);
        const block=await hmac(hash,secret,concatBytes(currentA,labelSeed));
        output=concatBytes(output,block);
    }
    return output.slice(0,length);
}
async function hkdfExtract(hash,salt,inputKeyMaterial){
    return salt&&salt.length||(salt=new Uint8Array(hashByteLength(hash))),hmac(hash,salt,inputKeyMaterial);
}
async function hkdfExpandLabel(hash,secret,label,context,length){
    const fullLabel=textEncoder.encode("tls13 "+label);
    return async function(hash,secret,info,length){
        const hashLen=hashByteLength(hash),roundCount=Math.ceil(length/hashLen);
        let output=new Uint8Array(0),previousBlock=new Uint8Array(0);
        for(let round=1;round<=roundCount;round++) previousBlock=await hmac(hash,secret,concatBytes(previousBlock,info,[round])),output=concatBytes(output,previousBlock);
        return output.slice(0,length);
    }(hash,secret,tlsBytes(uint16be(length),fullLabel.length,fullLabel,context.length,context),length);
}
async function generateKeyShare(group="P-256"){
    const algorithm="X25519"===group?{name:"X25519"}:{name:"ECDH",namedCurve:group};
    const keyPair=await crypto.subtle.generateKey(algorithm,!0,["deriveBits"]);
    const publicKeyRaw=await crypto.subtle.exportKey("raw",keyPair.publicKey);
    return {keyPair,publicKeyRaw:new Uint8Array(publicKeyRaw)};
}
async function deriveSharedSecret(privateKey,peerPublicKey,group="P-256"){
    const algorithm="X25519"===group?{name:"X25519"}:{name:"ECDH",namedCurve:group},
        peerKey=await crypto.subtle.importKey("raw",peerPublicKey,algorithm,!1,[]),
        bits="P-384"===group?384:"P-521"===group?528:256;
    return new Uint8Array(await crypto.subtle.deriveBits({name:algorithm.name,public:peerKey},privateKey,bits));
}
async function importAesGcmKey(key,usages){return crypto.subtle.importKey("raw",key,{name:"AES-GCM"},!1,usages);}
async function aesGcmEncryptWithKey(cryptoKey,initializationVector,plaintext,additionalData){
    return new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:initializationVector,additionalData,tagLength:128},cryptoKey,plaintext));
}
async function aesGcmDecryptWithKey(cryptoKey,initializationVector,ciphertext,additionalData){
    return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:initializationVector,additionalData,tagLength:128},cryptoKey,ciphertext));
}

function rotateLeft32(value,bits){return (value<<bits|value>>>32-bits)>>>0;}

function chachaQuarterRound(state,indexA,indexB,indexC,indexD){
    state[indexA]=state[indexA]+state[indexB]>>>0,state[indexD]=rotateLeft32(state[indexD]^state[indexA],16),state[indexC]=state[indexC]+state[indexD]>>>0,state[indexB]=rotateLeft32(state[indexB]^state[indexC],12),state[indexA]=state[indexA]+state[indexB]>>>0,state[indexD]=rotateLeft32(state[indexD]^state[indexA],8),state[indexC]=state[indexC]+state[indexD]>>>0,state[indexB]=rotateLeft32(state[indexB]^state[indexC],7);
}

function chacha20Block(key,counter,nonce){
    const state=new Uint32Array(16);
    state[0]=1634760805,state[1]=857760878,state[2]=2036477234,state[3]=1797285236;
    const keyView=new DataView(key.buffer,key.byteOffset,key.byteLength);
    for(let wordIndex=0;wordIndex<8;wordIndex++) state[4+wordIndex]=keyView.getUint32(4*wordIndex,!0);
    state[12]=counter;
    const nonceView=new DataView(nonce.buffer,nonce.byteOffset,nonce.byteLength);
    state[13]=nonceView.getUint32(0,!0),state[14]=nonceView.getUint32(4,!0),state[15]=nonceView.getUint32(8,!0);
    const workingState=new Uint32Array(state);
    for(let round=0;round<10;round++) chachaQuarterRound(workingState,0,4,8,12),chachaQuarterRound(workingState,1,5,9,13),chachaQuarterRound(workingState,2,6,10,14),chachaQuarterRound(workingState,3,7,11,15),chachaQuarterRound(workingState,0,5,10,15),chachaQuarterRound(workingState,1,6,11,12),chachaQuarterRound(workingState,2,7,8,13),chachaQuarterRound(workingState,3,4,9,14);
    for(let wordIndex=0;wordIndex<16;wordIndex++) workingState[wordIndex]=workingState[wordIndex]+state[wordIndex]>>>0;
    return new Uint8Array(workingState.buffer.slice(0));
}

function chacha20Xor(key,nonce,data){
    const output=new Uint8Array(data.length);
    let counter=1;
    for(let offset=0;offset<data.length;offset+=64){
        const block=chacha20Block(key,counter++,nonce),
            blockLength=Math.min(64,data.length-offset);
        for(let index=0;index<blockLength;index++) output[offset+index]=data[offset+index]^block[index];
    }
    return output;
}

function poly1305Mac(key,message){
    const rKey=function(rBytes){
        const clamped=new Uint8Array(rBytes);
        return clamped[3]&=15,clamped[7]&=15,clamped[11]&=15,clamped[15]&=15,clamped[4]&=252,clamped[8]&=252,clamped[12]&=252,clamped;
    }(key.slice(0,16)),
        sKey=key.slice(16,32);
    let accumulator=[0n,0n,0n,0n,0n];
    const rLimbs=[0x3ffffffn&BigInt(rKey[0]|rKey[1]<<8|rKey[2]<<16|rKey[3]<<24),0x3ffffffn&BigInt(rKey[3]>>2|rKey[4]<<6|rKey[5]<<14|rKey[6]<<22),0x3ffffffn&BigInt(rKey[6]>>4|rKey[7]<<4|rKey[8]<<12|rKey[9]<<20),0x3ffffffn&BigInt(rKey[9]>>6|rKey[10]<<2|rKey[11]<<10|rKey[12]<<18),0x3ffffffn&BigInt(rKey[13]|rKey[14]<<8|rKey[15]<<16)];
    for(let offset=0;offset<message.length;offset+=16){
        const chunk=message.slice(offset,offset+16),
            paddedChunk=new Uint8Array(17);
        paddedChunk.set(chunk),paddedChunk[chunk.length]=1,accumulator[0]+=BigInt(paddedChunk[0]|paddedChunk[1]<<8|paddedChunk[2]<<16|(3&paddedChunk[3])<<24),accumulator[1]+=BigInt(paddedChunk[3]>>2|paddedChunk[4]<<6|paddedChunk[5]<<14|(15&paddedChunk[6])<<22),accumulator[2]+=BigInt(paddedChunk[6]>>4|paddedChunk[7]<<4|paddedChunk[8]<<12|(63&paddedChunk[9])<<20),accumulator[3]+=BigInt(paddedChunk[9]>>6|paddedChunk[10]<<2|paddedChunk[11]<<10|paddedChunk[12]<<18),accumulator[4]+=BigInt(paddedChunk[13]|paddedChunk[14]<<8|paddedChunk[15]<<16|paddedChunk[16]<<24);
        const product=[0n,0n,0n,0n,0n];
        for(let accIndex=0;accIndex<5;accIndex++)
            for(let rIndex=0;rIndex<5;rIndex++){
                const limbIndex=accIndex+rIndex;
                limbIndex<5?product[limbIndex]+=accumulator[accIndex]*rLimbs[rIndex]:product[limbIndex-5]+=accumulator[accIndex]*rLimbs[rIndex]*5n;
            }
        let carry=0n;
        for(let index=0;index<5;index++) product[index]+=carry,accumulator[index]=0x3ffffffn&product[index],carry=product[index]>>26n;
        accumulator[0]+=5n*carry,carry=accumulator[0]>>26n,accumulator[0]&=0x3ffffffn,accumulator[1]+=carry;
    }
    let tagValue=accumulator[0]|accumulator[1]<<26n|accumulator[2]<<52n|accumulator[3]<<78n|accumulator[4]<<104n;
    tagValue=tagValue+sKey.reduce((total,byte,index)=>total+(BigInt(byte)<<BigInt(8*index)),0n)&(1n<<128n)-1n;
    const tag=new Uint8Array(16);
    for(let index=0;index<16;index++) tag[index]=Number(tagValue>>BigInt(8*index)&0xffn);
    return tag;
}

function chacha20Poly1305Encrypt(key,nonce,plaintext,additionalData){
    const polyKey=chacha20Block(key,0,nonce).slice(0,32),
        ciphertext=chacha20Xor(key,nonce,plaintext),
        aadPadding=(16-additionalData.length%16)%16,
        ciphertextPadding=(16-ciphertext.length%16)%16,
        macData=new Uint8Array(additionalData.length+aadPadding+ciphertext.length+ciphertextPadding+16);
    macData.set(additionalData,0),macData.set(ciphertext,additionalData.length+aadPadding);
    const lengthView=new DataView(macData.buffer,additionalData.length+aadPadding+ciphertext.length+ciphertextPadding);
    lengthView.setBigUint64(0,BigInt(additionalData.length),!0),lengthView.setBigUint64(8,BigInt(ciphertext.length),!0);
    const tag=poly1305Mac(polyKey,macData);
    return concatBytes(ciphertext,tag);
}

function chacha20Poly1305Decrypt(key,nonce,ciphertext,additionalData){
    if(ciphertext.length<16) throw new Error("Ciphertext too short");
    const tag=ciphertext.slice(-16),
        encryptedData=ciphertext.slice(0,-16),
        polyKey=chacha20Block(key,0,nonce).slice(0,32),
        aadPadding=(16-additionalData.length%16)%16,
        ciphertextPadding=(16-encryptedData.length%16)%16,
        macData=new Uint8Array(additionalData.length+aadPadding+encryptedData.length+ciphertextPadding+16);
    macData.set(additionalData,0),macData.set(encryptedData,additionalData.length+aadPadding);
    const lengthView=new DataView(macData.buffer,additionalData.length+aadPadding+encryptedData.length+ciphertextPadding);
    lengthView.setBigUint64(0,BigInt(additionalData.length),!0),lengthView.setBigUint64(8,BigInt(encryptedData.length),!0);
    const expectedTag=poly1305Mac(polyKey,macData);
    let diff=0;
    for(let index=0;index<16;index++) diff|=tag[index]^expectedTag[index];
    if(0!==diff) throw new Error("ChaCha20-Poly1305 authentication failed");
    return chacha20Xor(key,nonce,encryptedData);
}

const TLS_MAX_PLAINTEXT_FRAGMENT=16*1024;
function buildTlsRecord(contentType,fragment,version=TLS_VERSION_12){
    const data=toUint8(fragment);
    const record=new Uint8Array(5+data.byteLength);
    record[0]=contentType;
    record[1]=version>>8&255;
    record[2]=version&255;
    record[3]=data.byteLength>>8&255;
    record[4]=data.byteLength&255;
    record.set(data,5);
    return record;
}
function buildHandshakeMessage(handshakeType,body){return tlsBytes(handshakeType,(length=>[length>>16&255,length>>8&255,255&length])(body.length),body);}
class TlsRecordParser{
    constructor(){this.buffer=new Uint8Array(0);}
    feed(chunk){
        const bytes=toUint8(chunk);
        this.buffer=this.buffer.length?concatBytes(this.buffer,bytes):bytes;
    }
    next(){
        if(this.buffer.length<5) return null;
        const contentType=this.buffer[0],
            version=readUint16(this.buffer,1),
            length=readUint16(this.buffer,3);
        if(this.buffer.length<5+length) return null;
        const fragment=this.buffer.subarray(5,5+length);
        return this.buffer=this.buffer.subarray(5+length),{type:contentType,version,length,fragment};
    }
}
class TlsHandshakeParser{
    constructor(){this.buffer=new Uint8Array(0);}
    feed(chunk){
        const bytes=toUint8(chunk);
        this.buffer=this.buffer.length?concatBytes(this.buffer,bytes):bytes;
    }
    next(){
        if(this.buffer.length<4) return null;
        const handshakeType=this.buffer[0],
            length=readUint24(this.buffer,1);
        if(this.buffer.length<4+length) return null;
        const body=this.buffer.subarray(4,4+length),
            raw=this.buffer.subarray(0,4+length);
        return this.buffer=this.buffer.subarray(4+length),{type:handshakeType,length,body,raw};
    }
}

function parseServerHello(body){
    let offset=0;
    const legacyVersion=readUint16(body,offset);
    offset+=2;
    const serverRandom=body.slice(offset,offset+32);
    offset+=32;
    const sessionIdLength=body[offset++],
        sessionId=body.slice(offset,offset+sessionIdLength);
    offset+=sessionIdLength;
    const cipherSuite=readUint16(body,offset);
    offset+=2;
    const compression=body[offset++];
    let selectedVersion=legacyVersion,
        keyShare=null,
        alpn=null;
    if(offset<body.length){
        const extensionsLength=readUint16(body,offset);
        offset+=2;
        const extensionsEnd=offset+extensionsLength;
        for(;offset+4<=extensionsEnd;){
            const extensionType=readUint16(body,offset);
            offset+=2;
            const extensionLength=readUint16(body,offset);
            offset+=2;
            const extensionData=body.slice(offset,offset+extensionLength);
            if(offset+=extensionLength,extensionType===EXT_SUPPORTED_VERSIONS&&extensionLength>=2) selectedVersion=readUint16(extensionData,0);
            else if(extensionType===EXT_KEY_SHARE&&extensionLength>=4){
                const group=readUint16(extensionData,0),
                    keyLength=readUint16(extensionData,2);
                keyShare={group,key:extensionData.slice(4,4+keyLength)};
            }else extensionType===EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION&&extensionLength>=3&&(alpn=textDecoder.decode(extensionData.slice(3,3+extensionData[2])));
        }
    }
    const helloRetryRequestRandom=new Uint8Array([207,33,173,116,229,154,97,17,190,29,140,2,30,101,184,145,194,162,17,22,122,187,140,94,7,158,9,226,200,168,51,156]);
    return {version:legacyVersion,serverRandom,sessionId,cipherSuite,compression,selectedVersion,keyShare,alpn,isHRR:constantTimeEqual(serverRandom,helloRetryRequestRandom),isTls13:selectedVersion===TLS_VERSION_13};
}

function parseServerKeyExchange(body){
    let offset=1;
    const namedCurve=readUint16(body,offset);
    offset+=2;
    const keyLength=body[offset++];
    return {namedCurve,serverPublicKey:body.slice(offset,offset+keyLength)};
}

function extractLeafCertificate(body,hasContext=0){
    let offset=0;
    if(hasContext){
        const contextLength=body[offset++];
        offset+=contextLength;
    }
    if(offset+3>body.length) return null;
    const certificateListLength=readUint24(body,offset);
    if(offset+=3,!certificateListLength||offset+3>body.length) return null;
    const certificateLength=readUint24(body,offset);
    return offset+=3,certificateLength?body.slice(offset,offset+certificateLength):null;
}

function parseEncryptedExtensions(body){
    const parsed={alpn:null};
    let offset=2;
    const extensionsEnd=2+readUint16(body,0);
    for(;offset+4<=extensionsEnd;){
        const extensionType=readUint16(body,offset);
        offset+=2;
        const extensionLength=readUint16(body,offset);
        if(offset+=2,extensionType===EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION&&extensionLength>=3){
            const protocolLength=body[offset+2];
            protocolLength>0&&offset+3+protocolLength<=offset+extensionLength&&(parsed.alpn=textDecoder.decode(body.slice(offset+3,offset+3+protocolLength)));
        }
        offset+=extensionLength;
    }
    return parsed;
}

function buildClientHello(clientRandom,serverName,keyShares,{tls13:enableTls13=!0,tls12:enableTls12=!0,alpn=null,chacha=!0}={}){
    const cipherIds=[];
    enableTls13&&cipherIds.push(4865,4866,...(chacha?[4867]:[])),enableTls12&&cipherIds.push(49199,49200,49195,49196,...(chacha?[52392,52393]:[]));
    const cipherBytes=tlsBytes(...cipherIds.flatMap(uint16be)),
        extensions=[tlsBytes(255,1,0,1,0)];
    if(serverName){
        const serverNameBytes=textEncoder.encode(serverName),
            serverNameList=tlsBytes(0,uint16be(serverNameBytes.length),serverNameBytes);
        extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME),uint16be(serverNameList.length+2),uint16be(serverNameList.length),serverNameList));
    }
    extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS),0,2,1,0)),extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS),0,6,0,4,0,29,0,23));
    const signatureBytes=tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
    extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS),uint16be(signatureBytes.length+2),uint16be(signatureBytes.length),signatureBytes));
    const protocols=Array.isArray(alpn)?alpn.filter(Boolean):alpn?[alpn]:[];
    if(protocols.length){
        const alpnBytes=concatBytes(...protocols.map((protocol)=>{const protocolBytes=textEncoder.encode(protocol);return tlsBytes(protocolBytes.length,protocolBytes);}));
        extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),uint16be(alpnBytes.length+2),uint16be(alpnBytes.length),alpnBytes));
    }
    if(enableTls13&&keyShares){
        let keyShareBytes;
        if(extensions.push(enableTls12?tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS),0,5,4,3,4,3,3):tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS),0,3,2,3,4)),extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES),0,2,1,1)),keyShares?.x25519&&keyShares?.p256) keyShareBytes=concatBytes(tlsBytes(0,29,uint16be(keyShares.x25519.length),keyShares.x25519),tlsBytes(0,23,uint16be(keyShares.p256.length),keyShares.p256));
        else if(keyShares?.x25519) keyShareBytes=tlsBytes(0,29,uint16be(keyShares.x25519.length),keyShares.x25519);
        else if(keyShares?.p256) keyShareBytes=tlsBytes(0,23,uint16be(keyShares.p256.length),keyShares.p256);
        else{
            if(!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
            keyShareBytes=tlsBytes(0,23,uint16be(keyShares.length),keyShares);
        }
        extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE),uint16be(keyShareBytes.length+2),uint16be(keyShareBytes.length),keyShareBytes));
    }
    const extensionsBytes=concatBytes(...extensions);
    return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO,tlsBytes(uint16be(TLS_VERSION_12),clientRandom,0,uint16be(cipherBytes.length),cipherBytes,1,0,uint16be(extensionsBytes.length),extensionsBytes));
}
const uint64be=(sequenceNumber)=>{const bytes=new Uint8Array(8);return new DataView(bytes.buffer).setBigUint64(0,sequenceNumber,!1),bytes;},
    xorSequenceIntoIv=(initializationVector,sequenceNumber)=>{
        const nonce=initializationVector.slice(),
            sequenceBytes=uint64be(sequenceNumber);
        for(let index=0;index<8;index++) nonce[nonce.length-8+index]^=sequenceBytes[index];
        return nonce;
    },
    deriveTrafficKeys=(hash,secret,keyLen,ivLen)=>Promise.all([hkdfExpandLabel(hash,secret,"key",EMPTY_BYTES,keyLen),hkdfExpandLabel(hash,secret,"iv",EMPTY_BYTES,ivLen)]);
class TlsSocket{
    constructor(socket,options={}){
        if(this.socket=socket,this.serverName=options.serverName||"",this.supportTls13=!1!==options.tls13,this.supportTls12=!1!==options.tls12,!this.supportTls13&&!this.supportTls12) throw new Error("At least one TLS version must be enabled");
        this.alpnProtocols=Array.isArray(options.alpn)?options.alpn:options.alpn?[options.alpn]:null,this.allowChacha=options.allowChacha!==false,this.timeout=options.timeout??3e4,this.clientRandom=randomBytes(32),this.serverRandom=null,this.handshakeChunks=[],this.handshakeComplete=!1,this.negotiatedAlpn=null,this.cipherSuite=null,this.cipherConfig=null,this.isTls13=!1,this.masterSecret=null,this.handshakeSecret=null,this.clientWriteKey=null,this.serverWriteKey=null,this.clientWriteIv=null,this.serverWriteIv=null,this.clientHandshakeKey=null,this.serverHandshakeKey=null,this.clientHandshakeIv=null,this.serverHandshakeIv=null,this.clientAppKey=null,this.serverAppKey=null,this.clientAppIv=null,this.serverAppIv=null,this.clientWriteCryptoKey=null,this.serverWriteCryptoKey=null,this.clientHandshakeCryptoKey=null,this.serverHandshakeCryptoKey=null,this.clientAppCryptoKey=null,this.serverAppCryptoKey=null,this.clientSeqNum=0n,this.serverSeqNum=0n,this.recordParser=new TlsRecordParser,this.handshakeParser=new TlsHandshakeParser,this.keyPairs=new Map,this.ecdhKeyPair=null,this.sawCert=!1;
    }
    recordHandshake(chunk){this.handshakeChunks.push(chunk);}
    transcript(){return 1===this.handshakeChunks.length?this.handshakeChunks[0]:concatBytes(...this.handshakeChunks);}
    getCipherConfig(cipherSuite){return CIPHER_SUITES_BY_ID.get(cipherSuite)||null;}
    async readChunk(reader){return this.timeout?Promise.race([reader.read(),new Promise(((resolve,reject)=>setTimeout((()=>reject(new Error("TLS read timeout"))),this.timeout)))]):reader.read();}
    async readRecordsUntil(reader,predicate,closedError){
        for(;;){
            let record;
            for(;record=this.recordParser.next();)
                if(await predicate(record)) return;
            const {value,done}=await this.readChunk(reader);
            if(done) throw new Error(closedError);
            this.recordParser.feed(value);
        }
    }
    async readHandshakeUntil(reader,predicate,closedError){
        for(let message;message=this.handshakeParser.next();)
            if(await predicate(message)) return;
        return this.readRecordsUntil(reader,(async(record)=>{
            if(record.type===CONTENT_TYPE_ALERT){
                if(shouldIgnoreTlsAlert(record.fragment)) return;
                throw new Error(`TLS Alert: ${record.fragment[1]}`);
            }
            if(record.type===CONTENT_TYPE_HANDSHAKE){
                this.handshakeParser.feed(record.fragment);
                for(let message;message=this.handshakeParser.next();)
                    if(await predicate(message)) return 1;
            }
        }),closedError);
    }
    async acceptCertificate(certificate){if(!certificate?.length) throw new Error("Empty certificate");this.sawCert=!0;}
    async handshake(){
        const [p256Share,x25519Share]=await Promise.all([generateKeyShare("P-256"),generateKeyShare("X25519")]);
        this.keyPairs=new Map([[23,p256Share],[29,x25519Share]]),this.ecdhKeyPair=p256Share.keyPair;
        const reader=this.socket.readable.getReader(),
            writer=this.socket.writable.getWriter();
        try{
            const clientHello=buildClientHello(this.clientRandom,this.serverName,{x25519:x25519Share.publicKeyRaw,p256:p256Share.publicKeyRaw},{tls13:this.supportTls13,tls12:this.supportTls12,alpn:this.alpnProtocols,chacha:this.allowChacha});
            this.recordHandshake(clientHello),await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE,clientHello,TLS_VERSION_10));
            const serverHello=await this.receiveServerHello(reader);
            if(serverHello.isHRR) throw new Error("HelloRetryRequest is not supported");
            if(serverHello.keyShare?.group&&this.keyPairs.has(serverHello.keyShare.group)){
                const selectedKeyPair=this.keyPairs.get(serverHello.keyShare.group);
                this.ecdhKeyPair=selectedKeyPair.keyPair;
            }
            serverHello.isTls13?await this.handshakeTls13(reader,writer,serverHello):await this.handshakeTls12(reader,writer),this.handshakeComplete=!0;
        }finally{
            reader.releaseLock(),writer.releaseLock();
        }
    }
    async receiveServerHello(reader){
        for(;;){
            const {value,done}=await this.readChunk(reader);
            if(done) throw new Error("Connection closed waiting for ServerHello");
            let record;
            for(this.recordParser.feed(value);record=this.recordParser.next();){
                if(record.type===CONTENT_TYPE_ALERT){
                    if(shouldIgnoreTlsAlert(record.fragment)) continue;
                    throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
                }
                if(record.type!==CONTENT_TYPE_HANDSHAKE) continue;
                let message;
                for(this.handshakeParser.feed(record.fragment);message=this.handshakeParser.next();){
                    if(message.type!==HANDSHAKE_TYPE_SERVER_HELLO) continue;
                    this.recordHandshake(message.raw);
                    const serverHello=parseServerHello(message.body);
                    if(this.serverRandom=serverHello.serverRandom,this.cipherSuite=serverHello.cipherSuite,this.cipherConfig=this.getCipherConfig(serverHello.cipherSuite),this.isTls13=serverHello.isTls13,this.negotiatedAlpn=serverHello.alpn||null,!this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
                    return serverHello;
                }
            }
        }
    }
    async handshakeTls12(reader,writer){
        let serverKeyExchange=null;
        let sawServerHelloDone=!1;
        let clientCertRequested=!1;
        if(await this.readHandshakeUntil(reader,(async(message)=>{
            switch(message.type){
                case HANDSHAKE_TYPE_CERTIFICATE:{
                    this.recordHandshake(message.raw);
                    const certificate=extractLeafCertificate(message.body,1);
                    if(!certificate) throw new Error("Missing TLS 1.2 certificate");
                    await this.acceptCertificate(certificate);
                    break;
                }
                case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
                    this.recordHandshake(message.raw),serverKeyExchange=parseServerKeyExchange(message.body);
                    break;
                case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
                    return this.recordHandshake(message.raw),sawServerHelloDone=!0,1;
                case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
                    this.recordHandshake(message.raw),clientCertRequested=!0;
                    break;
                default:
                    this.recordHandshake(message.raw);
            }
        }),"Connection closed during TLS 1.2 handshake"),!this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
        const serverKeyExchangeData=serverKeyExchange;
        if(!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
        const curveName=GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
        if(!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
        const keyShare=this.keyPairs.get(serverKeyExchangeData.namedCurve);
        if(!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
        const preMasterSecret=await deriveSharedSecret(keyShare.keyPair.privateKey,serverKeyExchangeData.serverPublicKey,curveName),
            clientKeyExchange=buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,tlsBytes(keyShare.publicKeyRaw.length,keyShare.publicKeyRaw));
        if(clientCertRequested){
            const emptyCertificate=buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE,tlsBytes(0,0,0));
            this.recordHandshake(emptyCertificate),await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE,emptyCertificate));
        }
        this.recordHandshake(clientKeyExchange);
        const hashName=this.cipherConfig.hash;
        this.masterSecret=await tls12Prf(preMasterSecret,"master secret",concatBytes(this.clientRandom,this.serverRandom),48,hashName);
        const keyLen=this.cipherConfig.keyLen,
            ivLen=this.cipherConfig.ivLen,
            keyBlock=await tls12Prf(this.masterSecret,"key expansion",concatBytes(this.serverRandom,this.clientRandom),2*keyLen+2*ivLen,hashName);
        this.clientWriteKey=keyBlock.slice(0,keyLen),this.serverWriteKey=keyBlock.slice(keyLen,2*keyLen),this.clientWriteIv=keyBlock.slice(2*keyLen,2*keyLen+ivLen),this.serverWriteIv=keyBlock.slice(2*keyLen+ivLen,2*keyLen+2*ivLen);
        if(!this.cipherConfig.chacha) [this.clientWriteCryptoKey,this.serverWriteCryptoKey]=await Promise.all([importAesGcmKey(this.clientWriteKey,["encrypt"]),importAesGcmKey(this.serverWriteKey,["decrypt"])]);
        await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE,clientKeyExchange)),await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC,tlsBytes(1)));
        const clientVerifyData=await tls12Prf(this.masterSecret,"client finished",await digestBytes(hashName,this.transcript()),12,hashName),
            finishedMessage=buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED,clientVerifyData);
        this.recordHandshake(finishedMessage),await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE,await this.encryptTls12(finishedMessage,CONTENT_TYPE_HANDSHAKE)));
        let sawChangeCipherSpec=!1;
        await this.readRecordsUntil(reader,(async(record)=>{
            if(record.type===CONTENT_TYPE_ALERT){
                if(shouldIgnoreTlsAlert(record.fragment)) return;
                throw new Error(`TLS Alert: ${record.fragment[1]}`);
            }
            if(record.type===CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void(sawChangeCipherSpec=!0);
            if(record.type!==CONTENT_TYPE_HANDSHAKE||!sawChangeCipherSpec) return;
            const decrypted=await this.decryptTls12(record.fragment,CONTENT_TYPE_HANDSHAKE);
            if(decrypted[0]!==HANDSHAKE_TYPE_FINISHED) return;
            const verifyLength=readUint24(decrypted,1),
                verifyData=decrypted.slice(4,4+verifyLength),
                expectedVerifyData=await tls12Prf(this.masterSecret,"server finished",await digestBytes(hashName,this.transcript()),12,hashName);
            if(!constantTimeEqual(verifyData,expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
            return 1;
        }),"Connection closed waiting for TLS 1.2 Finished");
    }
    async handshakeTls13(reader,writer,serverHello){
        const groupName=GROUPS_BY_ID.get(serverHello.keyShare?.group);
        if(!groupName||!serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
        const hashName=this.cipherConfig.hash,
            hashLen=hashByteLength(hashName),
            keyLen=this.cipherConfig.keyLen,
            ivLen=this.cipherConfig.ivLen,
            sharedSecret=await deriveSharedSecret(this.ecdhKeyPair.privateKey,serverHello.keyShare.key,groupName),
            earlySecret=await hkdfExtract(hashName,null,new Uint8Array(hashLen)),
            derivedSecret=await hkdfExpandLabel(hashName,earlySecret,"derived",await digestBytes(hashName,EMPTY_BYTES),hashLen);
        this.handshakeSecret=await hkdfExtract(hashName,derivedSecret,sharedSecret);
        const transcriptHash=await digestBytes(hashName,this.transcript()),
            clientHandshakeTrafficSecret=await hkdfExpandLabel(hashName,this.handshakeSecret,"c hs traffic",transcriptHash,hashLen),
            serverHandshakeTrafficSecret=await hkdfExpandLabel(hashName,this.handshakeSecret,"s hs traffic",transcriptHash,hashLen);
        [this.clientHandshakeKey,this.clientHandshakeIv]=await deriveTrafficKeys(hashName,clientHandshakeTrafficSecret,keyLen,ivLen),[this.serverHandshakeKey,this.serverHandshakeIv]=await deriveTrafficKeys(hashName,serverHandshakeTrafficSecret,keyLen,ivLen);
        if(!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey,this.serverHandshakeCryptoKey]=await Promise.all([importAesGcmKey(this.clientHandshakeKey,["encrypt"]),importAesGcmKey(this.serverHandshakeKey,["decrypt"])]);
        const serverFinishedKey=await hkdfExpandLabel(hashName,serverHandshakeTrafficSecret,"finished",EMPTY_BYTES,hashLen);
        let serverFinishedReceived=!1;
        let clientCertRequested=!1;
        const handleHandshakeMessage=async(message)=>{
            switch(message.type){
                case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:{
                    const encryptedExtensions=parseEncryptedExtensions(message.body);
                    encryptedExtensions.alpn&&(this.negotiatedAlpn=encryptedExtensions.alpn),this.recordHandshake(message.raw);
                    break;
                }
                case HANDSHAKE_TYPE_CERTIFICATE:{
                    const certificate=extractLeafCertificate(message.body);
                    if(!certificate) throw new Error("Missing TLS 1.3 certificate");
                    await this.acceptCertificate(certificate),this.recordHandshake(message.raw);
                    break;
                }
                case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
                    this.recordHandshake(message.raw),clientCertRequested=!0;
                    break;
                case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
                    this.recordHandshake(message.raw);
                    break;
                case HANDSHAKE_TYPE_FINISHED:{
                    const expectedVerifyData=await hmac(hashName,serverFinishedKey,await digestBytes(hashName,this.transcript()));
                    if(!constantTimeEqual(expectedVerifyData,message.body)) throw new Error("TLS 1.3 server Finished verify failed");
                    this.recordHandshake(message.raw),serverFinishedReceived=!0;
                    break;
                }
                default:
                    this.recordHandshake(message.raw);
            }
        };
        await this.readRecordsUntil(reader,(async(record)=>{
            if(record.type===CONTENT_TYPE_CHANGE_CIPHER_SPEC||record.type===CONTENT_TYPE_HANDSHAKE) return;
            if(record.type===CONTENT_TYPE_ALERT){
                if(shouldIgnoreTlsAlert(record.fragment)) return;
                throw new Error(`TLS Alert: ${record.fragment[1]}`);
            }
            if(record.type!==CONTENT_TYPE_APPLICATION_DATA) return;
            const decrypted=await this.decryptTls13Handshake(record.fragment),
                innerType=decrypted[decrypted.length-1],
                plaintext=decrypted.slice(0,-1);
            if(innerType===CONTENT_TYPE_HANDSHAKE){
                this.handshakeParser.feed(plaintext);
                for(let message;message=this.handshakeParser.next();)
                    if(await handleHandshakeMessage(message),serverFinishedReceived) return 1;
            }
        }),"Connection closed during TLS 1.3 handshake");
        const applicationTranscriptHash=await digestBytes(hashName,this.transcript()),
            masterDerivedSecret=await hkdfExpandLabel(hashName,this.handshakeSecret,"derived",await digestBytes(hashName,EMPTY_BYTES),hashLen),
            masterSecret=await hkdfExtract(hashName,masterDerivedSecret,new Uint8Array(hashLen)),
            clientAppTrafficSecret=await hkdfExpandLabel(hashName,masterSecret,"c ap traffic",applicationTranscriptHash,hashLen),
            serverAppTrafficSecret=await hkdfExpandLabel(hashName,masterSecret,"s ap traffic",applicationTranscriptHash,hashLen);
        [this.clientAppKey,this.clientAppIv]=await deriveTrafficKeys(hashName,clientAppTrafficSecret,keyLen,ivLen),[this.serverAppKey,this.serverAppIv]=await deriveTrafficKeys(hashName,serverAppTrafficSecret,keyLen,ivLen);
        if(!this.cipherConfig.chacha) [this.clientAppCryptoKey,this.serverAppCryptoKey]=await Promise.all([importAesGcmKey(this.clientAppKey,["encrypt"]),importAesGcmKey(this.serverAppKey,["decrypt"])]);
        let clientFlightHandshake=EMPTY_BYTES;
        if(clientCertRequested) clientFlightHandshake=buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE,tlsBytes(0,0,0,0)),this.recordHandshake(clientFlightHandshake);
        const clientFinishedKey=await hkdfExpandLabel(hashName,clientHandshakeTrafficSecret,"finished",EMPTY_BYTES,hashLen),
            clientFinishedVerifyData=await hmac(hashName,clientFinishedKey,await digestBytes(hashName,this.transcript())),
            clientFinishedMessage=buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED,clientFinishedVerifyData);
        this.recordHandshake(clientFinishedMessage),await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA,await this.encryptTls13Handshake(concatBytes(clientFlightHandshake,clientFinishedMessage,[CONTENT_TYPE_HANDSHAKE])))),this.clientSeqNum=0n,this.serverSeqNum=0n;
    }
    async encryptTls12(plaintext,contentType){
        const sequenceNumber=this.clientSeqNum++,
            sequenceBytes=uint64be(sequenceNumber),
            additionalData=concatBytes(sequenceBytes,[contentType],uint16be(TLS_VERSION_12),uint16be(plaintext.length));
        if(this.cipherConfig.chacha){
            const nonce=xorSequenceIntoIv(this.clientWriteIv,sequenceNumber);
            return chacha20Poly1305Encrypt(this.clientWriteKey,nonce,plaintext,additionalData);
        }
        const explicitNonce=randomBytes(8);
        if(!this.clientWriteCryptoKey) this.clientWriteCryptoKey=await importAesGcmKey(this.clientWriteKey,["encrypt"]);
        return concatBytes(explicitNonce,await aesGcmEncryptWithKey(this.clientWriteCryptoKey,concatBytes(this.clientWriteIv,explicitNonce),plaintext,additionalData));
    }
    async decryptTls12(ciphertext,contentType){
        const sequenceNumber=this.serverSeqNum++,
            sequenceBytes=uint64be(sequenceNumber);
        if(this.cipherConfig.chacha){
            const nonce=xorSequenceIntoIv(this.serverWriteIv,sequenceNumber);
            return chacha20Poly1305Decrypt(this.serverWriteKey,nonce,ciphertext,concatBytes(sequenceBytes,[contentType],uint16be(TLS_VERSION_12),uint16be(ciphertext.length-16)));
        }
        const explicitNonce=ciphertext.subarray(0,8),
            encryptedData=ciphertext.subarray(8);
        if(!this.serverWriteCryptoKey) this.serverWriteCryptoKey=await importAesGcmKey(this.serverWriteKey,["decrypt"]);
        return aesGcmDecryptWithKey(this.serverWriteCryptoKey,concatBytes(this.serverWriteIv,explicitNonce),encryptedData,concatBytes(sequenceBytes,[contentType],uint16be(TLS_VERSION_12),uint16be(encryptedData.length-16)));
    }
    async encryptTls13Handshake(plaintext){
        const nonce=xorSequenceIntoIv(this.clientHandshakeIv,this.clientSeqNum++),
            additionalData=tlsBytes(CONTENT_TYPE_APPLICATION_DATA,3,3,uint16be(plaintext.length+16));
        if(this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey,nonce,plaintext,additionalData);
        if(!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey=await importAesGcmKey(this.clientHandshakeKey,["encrypt"]);
        return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey,nonce,plaintext,additionalData);
    }
    async decryptTls13Handshake(ciphertext){
        const nonce=xorSequenceIntoIv(this.serverHandshakeIv,this.serverSeqNum++),
            additionalData=tlsBytes(CONTENT_TYPE_APPLICATION_DATA,3,3,uint16be(ciphertext.length));
        const decrypted=this.cipherConfig.chacha?await chacha20Poly1305Decrypt(this.serverHandshakeKey,nonce,ciphertext,additionalData):await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey||(this.serverHandshakeCryptoKey=await importAesGcmKey(this.serverHandshakeKey,["decrypt"])),nonce,ciphertext,additionalData);
        let innerTypeIndex=decrypted.length-1;
        for(;innerTypeIndex>=0&&!decrypted[innerTypeIndex];) innerTypeIndex--;
        return innerTypeIndex<0?EMPTY_BYTES:decrypted.slice(0,innerTypeIndex+1);
    }
    async encryptTls13(data){
        const plaintext=concatBytes(data,[CONTENT_TYPE_APPLICATION_DATA]),
            nonce=xorSequenceIntoIv(this.clientAppIv,this.clientSeqNum++),
            additionalData=tlsBytes(CONTENT_TYPE_APPLICATION_DATA,3,3,uint16be(plaintext.length+16));
        if(this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey,nonce,plaintext,additionalData);
        if(!this.clientAppCryptoKey) this.clientAppCryptoKey=await importAesGcmKey(this.clientAppKey,["encrypt"]);
        return aesGcmEncryptWithKey(this.clientAppCryptoKey,nonce,plaintext,additionalData);
    }
    async decryptTls13(ciphertext){
        const nonce=xorSequenceIntoIv(this.serverAppIv,this.serverSeqNum++),
            additionalData=tlsBytes(CONTENT_TYPE_APPLICATION_DATA,3,3,uint16be(ciphertext.length)),
            plaintext=this.cipherConfig.chacha?await chacha20Poly1305Decrypt(this.serverAppKey,nonce,ciphertext,additionalData):await aesGcmDecryptWithKey(this.serverAppCryptoKey||(this.serverAppCryptoKey=await importAesGcmKey(this.serverAppKey,["decrypt"])),nonce,ciphertext,additionalData);
        let innerTypeIndex=plaintext.length-1;
        for(;innerTypeIndex>=0&&!plaintext[innerTypeIndex];) innerTypeIndex--;
        if(innerTypeIndex<0) return {data:EMPTY_BYTES,type:0};
        return {data:plaintext.slice(0,innerTypeIndex),type:plaintext[innerTypeIndex]};
    }
    async write(data){
        if(!this.handshakeComplete) throw new Error("Handshake not complete");
        const plaintext=toUint8(data);
        if(!plaintext.byteLength) return;
        const writer=this.socket.writable.getWriter();
        try{
            const records=[];
            for(let offset=0;offset<plaintext.byteLength;offset+=TLS_MAX_PLAINTEXT_FRAGMENT){
                const chunk=plaintext.subarray(offset,Math.min(offset+TLS_MAX_PLAINTEXT_FRAGMENT,plaintext.byteLength));
                const encrypted=this.isTls13?await this.encryptTls13(chunk):await this.encryptTls12(chunk,CONTENT_TYPE_APPLICATION_DATA);
                records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA,encrypted));
            }
            await writer.write(records.length===1?records[0]:concatBytes(...records));
        }finally{
            writer.releaseLock();
        }
    }
    async read(){
        for(;;){
            let record;
            for(;record=this.recordParser.next();){
                if(record.type===CONTENT_TYPE_ALERT){
                    if(record.fragment[1]===ALERT_CLOSE_NOTIFY) return null;
                    throw new Error(`TLS Alert: ${record.fragment[1]}`);
                }
                if(record.type!==CONTENT_TYPE_APPLICATION_DATA) continue;
                if(!this.isTls13) return this.decryptTls12(record.fragment,CONTENT_TYPE_APPLICATION_DATA);
                const {data,type}=await this.decryptTls13(record.fragment);
                if(type===CONTENT_TYPE_APPLICATION_DATA) return data;
                if(type===CONTENT_TYPE_ALERT){
                    if(data[1]===ALERT_CLOSE_NOTIFY) return null;
                    throw new Error(`TLS Alert: ${data[1]}`);
                }
                if(type!==CONTENT_TYPE_HANDSHAKE) continue;
                let message;
                for(this.handshakeParser.feed(data);message=this.handshakeParser.next();)
                    if(message.type!==HANDSHAKE_TYPE_NEW_SESSION_TICKET&&message.type===HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported");
            }
            const reader=this.socket.readable.getReader();
            try{
                const {value,done}=await this.readChunk(reader);
                if(done) return null;
                this.recordParser.feed(value);
            }finally{
                reader.releaseLock();
            }
        }
    }
    close(){this.socket.close();}
}

// HTTPS 代理建连：先自研 TLS 握手（不校验证书），再发 CONNECT
async function httpsProxyConnect(targetHost,targetPort,initialData,proxyConfig){
    const {username,password}=proxyConfig;
    const host=stripIPv6Brackets(proxyConfig.host),port=proxyConfig.port;
    let tlsSocket=null;
    const tlsServerName=isIpAddress(host)?"":stripIPv6Brackets(host);
    const openTls=async(allowChacha=false)=>{
        const proxySocket=connect({hostname:host,port});
        try{
            await proxySocket.opened;
            const socket=new TlsSocket(proxySocket,{serverName:tlsServerName,insecure:true,allowChacha});
            await socket.handshake();
            return socket;
        }catch(error){
            try{proxySocket.close();}catch(e){}
            throw error;
        }
    };
    try{
        try{
            tlsSocket=await openTls(false);
        }catch(error){
            if(!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message||`${error||""}`)) throw error;
            tlsSocket=await openTls(true);
        }

        const auth=username&&password?`Proxy-Authorization: Basic ${btoa(username+":"+password)}\r\n`:"";
        const target=`${stripIPv6Brackets(targetHost)}:${targetPort}`;
        const request=`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await tlsSocket.write(textEncoder.encode(request));

        let responseBuffer=new Uint8Array(0),headerEndIndex=-1,bytesRead=0;
        while(headerEndIndex===-1&&bytesRead<8192){
            const value=await tlsSocket.read();
            if(!value) throw new Error("HTTPS proxy closed before CONNECT response");
            responseBuffer=concatBytes(responseBuffer,value);
            bytesRead=responseBuffer.length;
            const crlfcrlf=responseBuffer.findIndex((_,i)=>i<responseBuffer.length-3&&responseBuffer[i]===0x0d&&responseBuffer[i+1]===0x0a&&responseBuffer[i+2]===0x0d&&responseBuffer[i+3]===0x0a);
            if(crlfcrlf!==-1) headerEndIndex=crlfcrlf+4;
        }
        if(headerEndIndex===-1) throw new Error("HTTPS proxy CONNECT response header too long or invalid");
        const statusMatch=textDecoder.decode(responseBuffer.slice(0,headerEndIndex)).split("\r\n")[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode=statusMatch?parseInt(statusMatch[1],10):NaN;
        if(!Number.isFinite(statusCode)||statusCode<200||statusCode>=300) throw new Error("HTTPS proxy refused connection: HTTP "+statusCode);

        if(toUint8(initialData).byteLength>0) await tlsSocket.write(toUint8(initialData));
        const bufferedData=bytesRead>headerEndIndex?responseBuffer.subarray(headerEndIndex,bytesRead):null;
        let closedSettled=!1,resolveClosed,rejectClosed;
        const settleClosed=(settle,value)=>{
            if(!closedSettled){
                closedSettled=!0;
                settle(value);
            }
        };
        const closed=new Promise((resolve,reject)=>{
            resolveClosed=resolve;
            rejectClosed=reject;
        });
        const close=()=>{
            try{tlsSocket.close();}catch(e){}
            settleClosed(resolveClosed);
        };
        const readable=new ReadableStream({
            async start(controller){
                try{
                    if(toUint8(bufferedData).byteLength>0) controller.enqueue(bufferedData);
                    while(true){
                        const data=await tlsSocket.read();
                        if(!data) break;
                        if(data.byteLength>0) controller.enqueue(data);
                    }
                    try{controller.close();}catch(e){}
                    settleClosed(resolveClosed);
                }catch(error){
                    try{controller.error(error);}catch(e){}
                    settleClosed(rejectClosed,error);
                }
            },
            cancel(){
                close();
            },
        });
        const writable=new WritableStream({
            async write(chunk){
                await tlsSocket.write(toUint8(chunk));
            },
            close,
            abort(error){
                close();
                if(error) settleClosed(rejectClosed,error);
            },
        });
        return {readable,writable,closed,close};
    }catch(error){
        try{tlsSocket?.close();}catch(e){}
        throw error;
    }
}

// ---- SSTP 客户端：把只出 SSTP 的 VPN Gate 家宽节点当出口用 ----
async function sstpConnect(proxyConfig,targetHost,targetPort){
    const username=proxyConfig.username??null,password=proxyConfig.password??null;
    let buffer=EMPTY_BYTES,pppId=1,socket=null,reader=null,writer=null;
    let settled=false,settleResolve,settleReject;
    const closed=new Promise((resolve,reject)=>{settleResolve=resolve;settleReject=reject;});
    const settle=(fn,value)=>{if(settled) return;settled=true;fn(value);};
    const close=()=>{
        try{reader?.cancel?.().catch?.(()=>{});}catch(e){}
        try{reader?.releaseLock?.();}catch(e){}
        try{writer?.close?.().catch?.(()=>{});}catch(e){}
        try{writer?.releaseLock?.();}catch(e){}
        try{socket?.close?.();}catch(e){}
        settle(settleResolve);
    };
    const readChunk=async()=>{
        const {value,done}=await reader.read();
        if(done||!value) throw new Error("SSTP connection closed");
        return toUint8(value);
    };
    const readN=async(length)=>{
        while(buffer.byteLength<length){
            const chunk=await readChunk();
            buffer=buffer.byteLength?concatBytes(buffer,chunk):chunk;
        }
        const result=buffer.subarray(0,length);
        buffer=buffer.subarray(length);
        return result;
    };
    const readLine=async()=>{
        for(;;){
            const index=buffer.indexOf(10);
            if(index>=0){
                const line=textDecoder.decode(buffer.subarray(0,index));
                buffer=buffer.subarray(index+1);
                return line.replace(/\r$/,"");
            }
            const chunk=await readChunk();
            buffer=buffer.byteLength?concatBytes(buffer,chunk):chunk;
        }
    };
    const readPacket=async(timeoutMs=PROXY_CONNECT_TIMEOUT_MS)=>{
        const header=await withTimeout(readN(4),timeoutMs,"SSTP read timeout");
        const length=readUint16(header,2)&0x0fff;
        if(length<4) throw new Error("Invalid SSTP packet length");
        return {isControl:(header[1]&1)!==0,body:length>4?await withTimeout(readN(length-4),timeoutMs,"SSTP body read timeout"):EMPTY_BYTES};
    };
    const packData=(pppFrame)=>{
        const length=6+pppFrame.byteLength,packet=new Uint8Array(length);
        packet.set([0x10,0x00,((length>>8)&0x0f)|0x80,length&0xff,0xff,0x03]);
        packet.set(pppFrame,6);
        return packet;
    };
    const buildPppConfig=(protocol,code,id,options=[])=>{
        const optionsLength=options.reduce((sum,option)=>sum+2+option.data.byteLength,0);
        const frame=new Uint8Array(6+optionsLength),view=new DataView(frame.buffer);
        view.setUint16(0,protocol);
        frame[2]=code;
        frame[3]=id;
        view.setUint16(4,4+optionsLength);
        options.reduce((offset,option)=>{
            frame[offset]=option.type;
            frame[offset+1]=2+option.data.byteLength;
            frame.set(option.data,offset+2);
            return offset+2+option.data.byteLength;
        },6);
        return frame;
    };
    const parsePppFrame=(data)=>{
        const offset=data.byteLength>=2&&data[0]===0xff&&data[1]===0x03?2:0;
        if(data.byteLength-offset<4) return null;
        const protocol=readUint16(data,offset);
        if(protocol===0x0021) return {protocol,ipPacket:data.subarray(offset+2)};
        if(data.byteLength-offset<6) return null;
        return {protocol,code:data[offset+2],id:data[offset+3],payload:data.subarray(offset+6),rawPacket:data.subarray(offset)};
    };
    const parsePppOptions=(data)=>{
        const options=[];
        for(let offset=0;offset+2<=data.byteLength;){
            const type=data[offset],length=data[offset+1];
            if(length<2||offset+length>data.byteLength) break;
            options.push({type,data:data.subarray(offset+2,offset+length)});
            offset+=length;
        }
        return options;
    };

    try{
        const serverHost=stripIPv6Brackets(proxyConfig.host),serverPort=proxyConfig.port;
        socket=connect({hostname:serverHost,port:serverPort},{secureTransport:"on",allowHalfOpen:false});
        await withTimeout(socket.opened,PROXY_CONNECT_TIMEOUT_MS,"SSTP server connection timeout");
        reader=socket.readable.getReader();
        writer=socket.writable.getWriter();

        const displayHost=serverHost.includes(":")?`[${serverHost}]`:serverHost;
        const httpRequest=textEncoder.encode(
            "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
            +`Host: ${Number(serverPort)===443?displayHost:displayHost+":"+serverPort}\r\n`
            +"Content-Length: 18446744073709551615\r\n"
            +`SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
        );
        const encapsulation=new Uint8Array(2);
        new DataView(encapsulation.buffer).setUint16(0,1);
        const maxReceiveUnit=new Uint8Array(2);
        new DataView(maxReceiveUnit.buffer).setUint16(0,1500);
        const connectRequest=new Uint8Array(12+encapsulation.byteLength);
        const connectView=new DataView(connectRequest.buffer);
        connectRequest[0]=0x10;
        connectRequest[1]=0x01;
        connectView.setUint16(2,connectRequest.byteLength|0x8000);
        connectView.setUint16(4,0x0001);
        connectView.setUint16(6,1);
        connectRequest[9]=1;
        connectView.setUint16(10,4+encapsulation.byteLength);
        connectRequest.set(encapsulation,12);

        await withTimeout(writer.write(concatBytes(
            httpRequest,
            connectRequest,
            packData(buildPppConfig(0xc021,1,pppId++,[{type:1,data:maxReceiveUnit}]))
        )),PROXY_CONNECT_TIMEOUT_MS,"SSTP handshake request timeout");

        const statusLine=await withTimeout(readLine(),PROXY_CONNECT_TIMEOUT_MS,"SSTP HTTP handshake timeout");
        for(;;){
            const line=await withTimeout(readLine(),PROXY_CONNECT_TIMEOUT_MS,"SSTP HTTP header timeout");
            if(line==="") break;
        }
        if(!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error("SSTP HTTP handshake failed: "+(statusLine||"invalid status line"));

        let localLcpAcked=false,peerLcpAcked=false,needsPap=false,papSent=false,papDone=false,ipcpSent=false,ipcpDone=false,localAddress=null;
        const sendPap=async()=>{
            if(!localLcpAcked||!peerLcpAcked||!needsPap||papSent) return;
            if(username===null||password===null) throw new Error("SSTP server requires PAP authentication");
            const userBytes=textEncoder.encode(username),passBytes=textEncoder.encode(password);
            if(userBytes.byteLength>255||passBytes.byteLength>255) throw new Error("SSTP username or password too long");
            const papLength=6+userBytes.byteLength+passBytes.byteLength;
            const frame=new Uint8Array(2+papLength),view=new DataView(frame.buffer);
            view.setUint16(0,0xc023);
            frame[2]=1;
            frame[3]=pppId++;
            view.setUint16(4,papLength);
            frame[6]=userBytes.byteLength;
            frame.set(userBytes,7);
            frame[7+userBytes.byteLength]=passBytes.byteLength;
            frame.set(passBytes,8+userBytes.byteLength);
            await withTimeout(writer.write(packData(frame)),PROXY_CONNECT_TIMEOUT_MS,"SSTP PAP request timeout");
            papSent=true;
        };
        const startIpcp=async()=>{
            if(!localLcpAcked||!peerLcpAcked||ipcpSent||(needsPap&&!papDone)) return;
            await withTimeout(writer.write(packData(buildPppConfig(0x8021,1,pppId++,[{type:3,data:new Uint8Array(4)}]))),PROXY_CONNECT_TIMEOUT_MS,"SSTP IPCP request timeout");
            ipcpSent=true;
        };

        for(let round=0;round<50&&!ipcpDone;round++){
            const packet=await readPacket(PROXY_CONNECT_TIMEOUT_MS);
            if(packet.isControl) continue;
            const ppp=parsePppFrame(packet.body);
            if(!ppp) continue;

            if(ppp.protocol===0xc021){
                if(ppp.code===1){
                    const authOption=parsePppOptions(ppp.payload).find((option)=>option.type===3);
                    if(authOption?.data?.byteLength>=2){
                        const authProtocol=readUint16(authOption.data);
                        if(authProtocol!==0xc023) throw new Error("SSTP unsupported PPP auth protocol: 0x"+authProtocol.toString(16));
                        needsPap=true;
                    }
                    const ack=new Uint8Array(ppp.rawPacket);
                    ack[2]=2;
                    await withTimeout(writer.write(packData(ack)),PROXY_CONNECT_TIMEOUT_MS,"SSTP LCP ack timeout");
                    peerLcpAcked=true;
                    await sendPap();
                    await startIpcp();
                }else if(ppp.code===2){
                    localLcpAcked=true;
                    await sendPap();
                    await startIpcp();
                }
                continue;
            }

            if(ppp.protocol===0xc023){
                if(ppp.code===2){
                    papDone=true;
                    await startIpcp();
                }else if(ppp.code===3) throw new Error("SSTP PAP authentication failed");
                continue;
            }

            if(ppp.protocol===0x8021){
                if(ppp.code===1){
                    const ack=new Uint8Array(ppp.rawPacket);
                    ack[2]=2;
                    await withTimeout(writer.write(packData(ack)),PROXY_CONNECT_TIMEOUT_MS,"SSTP IPCP ack timeout");
                    await startIpcp();
                }else if(ppp.code===3){
                    const addressOption=parsePppOptions(ppp.payload).find((option)=>option.type===3);
                    if(addressOption?.data?.byteLength===4){
                        localAddress=[...addressOption.data].join(".");
                        await withTimeout(writer.write(packData(buildPppConfig(0x8021,1,pppId++,[{type:3,data:addressOption.data}]))),PROXY_CONNECT_TIMEOUT_MS,"SSTP IPCP address request timeout");
                        ipcpSent=true;
                    }
                }else if(ppp.code===2){
                    const addressOption=parsePppOptions(ppp.payload).find((option)=>option.type===3);
                    if(addressOption?.data?.byteLength===4) localAddress=[...addressOption.data].join(".");
                    ipcpDone=true;
                }
            }
        }
        if(!localAddress) throw new Error("SSTP did not assign an IPv4 address");

        const target=stripIPv6Brackets(targetHost);
        const targetIp=isIPv4(target)?target:await resolveIPv4(target);
        if(!targetIp) throw new Error("SSTP cannot resolve "+targetHost+" to an IPv4 address");

        const sourcePort=10000+(randomUint16()%50000);
        const sourceBytes=new Uint8Array(String(localAddress).split(".").map(Number));
        const targetBytes=new Uint8Array(String(targetIp).split(".").map(Number));
        let sequence=readUint32(crypto.getRandomValues(new Uint8Array(4)));
        let ackNumber=0;
        const ipHeaderTemplate=new Uint8Array(20);
        ipHeaderTemplate.set([0x45,0x00,0x00,0x00,0x00,0x00,0x40,0x00,64,6]);
        ipHeaderTemplate.set(sourceBytes,12);
        ipHeaderTemplate.set(targetBytes,16);
        const tcpPseudoHeader=new Uint8Array(1432);
        tcpPseudoHeader.set(sourceBytes);
        tcpPseudoHeader.set(targetBytes,4);
        tcpPseudoHeader[9]=6;
        const buildTcpFrame=(flags,payload=EMPTY_BYTES)=>{
            const bytes=toUint8(payload);
            const payloadLength=bytes.byteLength;
            const tcpLength=20+payloadLength;
            const ipLength=20+tcpLength;
            const sstpLength=8+ipLength;
            const frame=new Uint8Array(sstpLength);
            const view=new DataView(frame.buffer);
            frame.set([0x10,0x00,((sstpLength>>8)&0x0f)|0x80,sstpLength&0xff,0xff,0x03,0x00,0x21]);
            frame.set(ipHeaderTemplate,8);
            view.setUint16(10,ipLength);
            view.setUint16(12,randomUint16());
            view.setUint16(18,internetChecksum(frame,8,20));
            view.setUint16(28,sourcePort);
            view.setUint16(30,targetPort);
            view.setUint32(32,sequence);
            view.setUint32(36,ackNumber);
            frame[40]=0x50;
            frame[41]=flags;
            view.setUint16(42,65535);
            if(payloadLength) frame.set(bytes,48);
            tcpPseudoHeader[10]=tcpLength>>8;
            tcpPseudoHeader[11]=tcpLength&0xff;
            tcpPseudoHeader.set(frame.subarray(28,28+tcpLength),12);
            view.setUint16(44,internetChecksum(tcpPseudoHeader,0,12+tcpLength));
            return frame;
        };
        const matchInbound=(ipPacket)=>{
            if(ipPacket.byteLength<40||ipPacket[9]!==6) return null;
            const headerLength=(ipPacket[0]&0x0f)*4;
            if(ipPacket.byteLength<headerLength+20) return null;
            if(readUint16(ipPacket,headerLength)!==targetPort) return null;
            if(readUint16(ipPacket,headerLength+2)!==sourcePort) return null;
            return {
                flags:ipPacket[headerLength+13],
                sequence:readUint32(ipPacket,headerLength+4),
                payloadOffset:headerLength+((ipPacket[headerLength+12]>>4)&0x0f)*4,
            };
        };

        await withTimeout(writer.write(buildTcpFrame(0x02)),PROXY_CONNECT_TIMEOUT_MS,"SSTP TCP SYN timeout");
        sequence=(sequence+1)>>>0;

        let tcpReady=false;
        for(let attempt=0;attempt<30;attempt++){
            const packet=await readPacket(PROXY_CONNECT_TIMEOUT_MS);
            if(packet.isControl) continue;
            const ppp=parsePppFrame(packet.body);
            if(!ppp||ppp.protocol!==0x0021) continue;
            const tcp=matchInbound(ppp.ipPacket);
            if(!tcp||(tcp.flags&0x12)!==0x12) continue;
            ackNumber=(tcp.sequence+1)>>>0;
            await withTimeout(writer.write(buildTcpFrame(0x10)),PROXY_CONNECT_TIMEOUT_MS,"SSTP TCP ACK timeout");
            tcpReady=true;
            break;
        }
        if(!tcpReady) throw new Error("SSTP inner TCP handshake timeout");

        let streamController=null;
        const readable=new ReadableStream({
            start(controller){streamController=controller;},
            cancel(){close();},
        });

        (async()=>{
            try{
                let pendingChunks=[],pendingLength=0;
                const flush=()=>{
                    if(!pendingLength) return;
                    if(!streamController) throw new Error("SSTP readable stream not ready");
                    streamController.enqueue(pendingChunks.length===1?pendingChunks[0]:concatBytes(...pendingChunks));
                    pendingChunks=[];
                    pendingLength=0;
                    writer.write(buildTcpFrame(0x10)).catch(()=>{});
                };
                for(;;){
                    const packet=await readPacket(60000);
                    if(packet.isControl) continue;
                    const ppp=parsePppFrame(packet.body);
                    if(!ppp||ppp.protocol!==0x0021) continue;
                    const inbound=matchInbound(ppp.ipPacket);
                    if(!inbound) continue;
                    if(inbound.payloadOffset<ppp.ipPacket.byteLength){
                        const payload=ppp.ipPacket.subarray(inbound.payloadOffset);
                        if(payload.byteLength){
                            ackNumber=(inbound.sequence+payload.byteLength)>>>0;
                            pendingChunks.push(new Uint8Array(payload));
                            pendingLength+=payload.byteLength;
                        }
                    }
                    if(inbound.flags&0x01){
                        flush();
                        ackNumber=(ackNumber+1)>>>0;
                        writer.write(buildTcpFrame(0x11)).catch(()=>{});
                        const controller=streamController;
                        if(controller){try{controller.close();}catch(e){}}
                        close();
                        return;
                    }
                    if(buffer.byteLength<4||pendingLength>=32768) flush();
                }
            }catch(error){
                const controller=streamController;
                if(controller){try{controller.error(error);}catch(e){}}
                settle(settleReject,error);
                try{socket?.close?.();}catch(e){}
            }
        })();

        const writable=new WritableStream({
            async write(chunk){
                const bytes=toUint8(chunk);
                if(!bytes.byteLength) return;
                if(bytes.byteLength<=SSTP_TCP_MSS){
                    await writer.write(buildTcpFrame(0x18,bytes));
                    sequence=(sequence+bytes.byteLength)>>>0;
                    return;
                }
                const frames=[];
                for(let offset=0;offset<bytes.byteLength;offset+=SSTP_TCP_MSS){
                    const segment=bytes.subarray(offset,Math.min(offset+SSTP_TCP_MSS,bytes.byteLength));
                    frames.push(buildTcpFrame(0x18,segment));
                    sequence=(sequence+segment.byteLength)>>>0;
                }
                await writer.write(concatBytes(...frames));
            },
            close(){return writer.write(buildTcpFrame(0x11)).catch(()=>{});},
            abort(error){
                close();
                if(error) settle(settleReject,error);
            },
        });

        return {readable,writable,closed,close};
    }catch(error){
        close();
        throw error;
    }
}

// ---- TURN 中继（RFC 6062）：CONNECT 方式让 TURN 服务器替我们连目标 ----
const TURN_STUN_MAGIC_COOKIE=new Uint8Array([0x21,0x12,0xa4,0x42]);
const TURN_STUN_TYPE={
    ALLOCATE_REQUEST:0x0003,ALLOCATE_SUCCESS:0x0103,ALLOCATE_ERROR:0x0113,
    CREATE_PERMISSION_REQUEST:0x0008,CREATE_PERMISSION_SUCCESS:0x0108,
    CONNECT_REQUEST:0x000a,CONNECT_SUCCESS:0x010a,
    CONNECTION_BIND_REQUEST:0x000b,CONNECTION_BIND_SUCCESS:0x010b,
};
const TURN_STUN_ATTR={
    USERNAME:0x0006,MESSAGE_INTEGRITY:0x0008,ERROR_CODE:0x0009,
    XOR_PEER_ADDRESS:0x0012,REALM:0x0014,NONCE:0x0015,
    REQUESTED_TRANSPORT:0x0019,CONNECTION_ID:0x002a,
};
function turnStunPadding(length){return -length&3;}
function createTurnStunAttribute(type,value){
    const body=toUint8(value);
    const attribute=new Uint8Array(4+body.byteLength+turnStunPadding(body.byteLength));
    const view=new DataView(attribute.buffer);
    view.setUint16(0,type);
    view.setUint16(2,body.byteLength);
    attribute.set(body,4);
    return attribute;
}
function createTurnStunMessage(type,transactionId,attributes){
    const body=concatBytes(...attributes);
    const header=new Uint8Array(20);
    const view=new DataView(header.buffer);
    view.setUint16(0,type);
    view.setUint16(2,body.byteLength);
    header.set(TURN_STUN_MAGIC_COOKIE,4);
    header.set(transactionId,8);
    return concatBytes(header,body);
}
function parseTurnErrorCode(data){return data?.byteLength>=4?(data[2]&7)*100+data[3]:0;}
function randomTurnTransactionId(){return crypto.getRandomValues(new Uint8Array(12));}
async function addTurnMessageIntegrity(message,key){
    const signedMessage=new Uint8Array(message);
    const view=new DataView(signedMessage.buffer);
    view.setUint16(2,view.getUint16(2)+24);
    const hmacKey=await crypto.subtle.importKey("raw",key,{name:"HMAC",hash:"SHA-1"},false,["sign"]);
    const signature=await crypto.subtle.sign("HMAC",hmacKey,signedMessage);
    return concatBytes(signedMessage,createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY,new Uint8Array(signature)));
}
async function readTurnStunMessage(reader,bufferedData=null,timeoutMessage="TURN response timeout"){
    let buffer=bufferedData?.byteLength?toUint8(bufferedData):new Uint8Array(0);
    const pull=async()=>{
        const {done,value}=await withTimeout(reader.read(),PROXY_CONNECT_TIMEOUT_MS,timeoutMessage);
        if(done) throw new Error("TURN server closed connection");
        if(value?.byteLength) buffer=concatBytes(buffer,value);
    };
    while(buffer.byteLength<20) await pull();

    const messageLength=20+((buffer[2]<<8)|buffer[3]);
    if(messageLength>65555) throw new Error("TURN response too large");
    while(buffer.byteLength<messageLength) await pull();
    const messageBuffer=buffer.subarray(0,messageLength);
    if(TURN_STUN_MAGIC_COOKIE.some((value,index)=>messageBuffer[4+index]!==value)) throw new Error("Invalid TURN/STUN response");

    const view=new DataView(messageBuffer.buffer,messageBuffer.byteOffset,messageBuffer.byteLength);
    const attributes={};
    for(let offset=20;offset+4<=messageLength;){
        const type=view.getUint16(offset);
        const length=view.getUint16(offset+2);
        if(offset+4+length>messageBuffer.byteLength) break;
        attributes[type]=messageBuffer.slice(offset+4,offset+4+length);
        offset+=4+length+turnStunPadding(length);
    }
    return {
        message:{type:view.getUint16(0),attributes},
        extraData:buffer.byteLength>messageLength?buffer.subarray(messageLength):null,
    };
}
async function writeTurnBytes(writer,bytes,timeoutMessage){
    await withTimeout(writer.write(bytes),PROXY_CONNECT_TIMEOUT_MS,timeoutMessage);
}
async function turnConnect(proxyConfig,targetHost,targetPort){
    const username=proxyConfig.username??null,password=proxyConfig.password??null;
    const target=stripIPv6Brackets(targetHost);
    const targetIp=isIPv4(target)?target:await resolveIPv4(target);
    if(!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

    const turnHost=stripIPv6Brackets(proxyConfig.host);
    let controlSocket=null,dataSocket=null,controlWriter=null,controlReader=null,dataWriter=null,dataReader=null,dataReaderReleased=false;
    const close=()=>{
        try{controlSocket?.close?.();}catch(e){}
        try{dataSocket?.close?.();}catch(e){}
    };
    const releaseDataReader=()=>{
        if(dataReaderReleased) return;
        dataReaderReleased=true;
        try{dataReader?.releaseLock?.();}catch(e){}
    };

    try{
        controlSocket=connect({hostname:turnHost,port:proxyConfig.port});
        await withTimeout(controlSocket.opened,PROXY_CONNECT_TIMEOUT_MS,"TURN server connection timeout");
        controlWriter=controlSocket.writable.getWriter();
        controlReader=controlSocket.readable.getReader();

        const xorPeerAddress=new Uint8Array(8);
        xorPeerAddress[1]=1;
        new DataView(xorPeerAddress.buffer).setUint16(2,targetPort^0x2112);
        targetIp.split(".").forEach((value,index)=>{
            xorPeerAddress[4+index]=Number(value)^TURN_STUN_MAGIC_COOKIE[index];
        });
        const peerAddress=createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS,xorPeerAddress);
        const requestedTransport=new Uint8Array([6,0,0,0]);

        await writeTurnBytes(controlWriter,createTurnStunMessage(
            TURN_STUN_TYPE.ALLOCATE_REQUEST,
            randomTurnTransactionId(),
            [createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT,requestedTransport)]
        ),"TURN Allocate request timeout");

        let turnResponse=await readTurnStunMessage(controlReader,null,"TURN Allocate response timeout");
        let message=turnResponse.message;
        let bufferedData=turnResponse.extraData;
        let integrityKey=null;
        let authAttributes=[];
        const sign=(messageToSign)=>integrityKey?addTurnMessageIntegrity(messageToSign,integrityKey):Promise.resolve(messageToSign);

        if(
            message.type===TURN_STUN_TYPE.ALLOCATE_ERROR
            &&username!==null
            &&password!==null
            &&parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE])===401
        ){
            const realmBytes=message.attributes[TURN_STUN_ATTR.REALM];
            const nonce=message.attributes[TURN_STUN_ATTR.NONCE];
            if(!realmBytes||!nonce?.byteLength) throw new Error("TURN authentication challenge is missing realm or nonce");

            const realm=textDecoder.decode(realmBytes);
            integrityKey=new Uint8Array(await crypto.subtle.digest("MD5",textEncoder.encode(`${username}:${realm}:${password}`)));
            authAttributes=[
                createTurnStunAttribute(TURN_STUN_ATTR.USERNAME,textEncoder.encode(username)),
                createTurnStunAttribute(TURN_STUN_ATTR.REALM,textEncoder.encode(realm)),
                createTurnStunAttribute(TURN_STUN_ATTR.NONCE,nonce),
            ];

            const allocateRequest=await addTurnMessageIntegrity(createTurnStunMessage(
                TURN_STUN_TYPE.ALLOCATE_REQUEST,
                randomTurnTransactionId(),
                [
                    createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT,requestedTransport),
                    ...authAttributes,
                ]
            ),integrityKey);
            const pipelinedMessages=await Promise.all([
                sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST,randomTurnTransactionId(),[peerAddress,...authAttributes])),
                sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST,randomTurnTransactionId(),[peerAddress,...authAttributes])),
            ]);
            await writeTurnBytes(controlWriter,concatBytes(allocateRequest,...pipelinedMessages),"TURN authenticated Allocate request timeout");
            turnResponse=await readTurnStunMessage(controlReader,bufferedData,"TURN authenticated Allocate response timeout");
            message=turnResponse.message;
            bufferedData=turnResponse.extraData;
        }else if(message.type===TURN_STUN_TYPE.ALLOCATE_SUCCESS){
            const pipelinedMessages=await Promise.all([
                sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST,randomTurnTransactionId(),[peerAddress,...authAttributes])),
                sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST,randomTurnTransactionId(),[peerAddress,...authAttributes])),
            ]);
            if(pipelinedMessages.length) await writeTurnBytes(controlWriter,concatBytes(...pipelinedMessages),"TURN pipelined request timeout");
        }

        if(message.type!==TURN_STUN_TYPE.ALLOCATE_SUCCESS){
            const errorCode=parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
            throw new Error(errorCode?`TURN Allocate failed with ${errorCode}`:"TURN Allocate failed");
        }

        dataSocket=connect({hostname:turnHost,port:proxyConfig.port});
        turnResponse=await readTurnStunMessage(controlReader,bufferedData,"TURN CreatePermission response timeout");
        message=turnResponse.message;
        bufferedData=turnResponse.extraData;
        if(message.type!==TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error("TURN CreatePermission failed");

        turnResponse=await readTurnStunMessage(controlReader,bufferedData,"TURN CONNECT response timeout");
        message=turnResponse.message;
        bufferedData=turnResponse.extraData;
        if(message.type!==TURN_STUN_TYPE.CONNECT_SUCCESS||!message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error("TURN CONNECT failed");

        await withTimeout(dataSocket.opened,PROXY_CONNECT_TIMEOUT_MS,"TURN data connection timeout");
        dataWriter=dataSocket.writable.getWriter();
        dataReader=dataSocket.readable.getReader();
        await writeTurnBytes(dataWriter,await sign(createTurnStunMessage(
            TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
            randomTurnTransactionId(),
            [
                createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID,message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
                ...authAttributes,
            ]
        )),"TURN ConnectionBind request timeout");

        turnResponse=await readTurnStunMessage(dataReader,null,"TURN ConnectionBind response timeout");
        message=turnResponse.message;
        const extraPayload=turnResponse.extraData;
        if(message.type!==TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error("TURN ConnectionBind failed");

        controlWriter.releaseLock();
        controlWriter=null;
        controlReader.releaseLock();
        controlReader=null;
        dataWriter.releaseLock();
        dataWriter=null;

        const readable=new ReadableStream({
            start(controller){
                if(extraPayload?.byteLength) controller.enqueue(extraPayload);
            },
            pull(controller){
                return dataReader.read().then(({done,value})=>{
                    if(done){
                        releaseDataReader();
                        controller.close();
                    }else if(value?.byteLength) controller.enqueue(new Uint8Array(value));
                });
            },
            cancel(){
                try{dataReader?.cancel?.();}catch(e){}
                releaseDataReader();
                close();
            },
        });

        return {readable,writable:dataSocket.writable,closed:dataSocket.closed,close};
    }catch(error){
        try{controlWriter?.releaseLock?.();}catch(e){}
        try{controlReader?.releaseLock?.();}catch(e){}
        try{dataWriter?.releaseLock?.();}catch(e){}
        releaseDataReader();
        close();
        throw error;
    }
}

// 统一入口：按其它代理类型建立连接，返回可直接当 socket 用的对象
async function connectViaProxy(proxyConfig,targetHost,targetPort,initialData){
    if(!proxyConfig||!proxyConfig.host) throw new Error("empty chain proxy config");
    const type=proxyConfig.type||"socks5";
    let socket;
    if(type==="sstp"){
        socket=await sstpConnect(proxyConfig,targetHost,targetPort);
    }else if(type==="turn"){
        socket=await turnConnect(proxyConfig,targetHost,targetPort);
    }else if(type==="http"||type==="https"){
        // HTTPS 代理若填的是 IP（绝大多数公共 HTTPS 代理都是），走自研 TLS 客户端，
        // 避免 CF 内置 secureTransport 的证书校验导致握手失败；域名仍走内置 TLS。
        socket=type==="https"&&isIpAddress(proxyConfig.host)
            ?await httpsProxyConnect(targetHost,targetPort,null,proxyConfig)
            :await httpConnect(proxyConfig,targetHost,targetPort,type==="https");
    }else{
        const raw=connect({hostname:stripIPv6Brackets(proxyConfig.host),port:proxyConfig.port});
        try{
            const {writer,reader}=await socks5Connect(raw,proxyConfig,targetHost,targetPort,2500);
            writer.releaseLock();
            reader.releaseLock();
            socket=raw;
        }catch(error){
            try{raw.close();}catch(e){}
            throw error;
        }
    }
    const payload=toUint8(initialData);
    if(payload.byteLength){
        const writer=socket.writable.getWriter();
        await writer.write(payload);
        writer.releaseLock();
    }
    return socket;
}

const connectDirect=async(hostname,portNum,data)=>{const sock=connect({hostname,port:portNum});await sock.opened;const w=sock.writable.getWriter();await w.write(data);w.releaseLock();return sock;};
const connectStreams=async(remoteSocket,webSocket,headerData,retryFunc,userCfg)=>{
    let header=headerData,hasData=false,dataPromiseResolve;
    const dataPromise=new Promise((resolve)=>(dataPromiseResolve=resolve));
    const timeoutId=setTimeout(()=>{if(!hasData) dataPromiseResolve(false);},userCfg?.fallbackTimeout||100);
    remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk,controller){
            clearTimeout(timeoutId);hasData=true;dataPromiseResolve(true);
            if(webSocket.readyState!==1) controller.error("ws not open");
            if(header){
                const response=new Uint8Array(header.length+chunk.byteLength);
                response.set(header,0);response.set(chunk,header.length);
                webSocket.send(headerData?response.buffer:chunk);header=null;
            }else webSocket.send(chunk);
        },abort(){}
    })).catch(()=>{try{webSocket.readyState===1&&webSocket.close();}catch{}});
    const receivedData=await dataPromise;if(!receivedData&&retryFunc) await retryFunc();
};

const connectParallel=async(host,port,payload,order,mode,proxyCfg,proxyIp,getOrderFn,tryConnectFn,ws,header,userCfg,remoteVar,setRemote,retryFn)=>{
    const tryConnect=async(type)=>{
        try{
            if(type==="direct") return await connectDirect(host,port,payload);
            if(type==="s5"&&proxyCfg) return await tryConnectFn(proxyCfg,host,port,payload);
            if(type==="proxy"&&proxyIp){const [ph,pp=port]=proxyIp.split(":");return await connectDirect(ph,+pp||port,payload);}
        }catch{}return null;
    };
    const tryNext=async(index)=>{if(index>=order.length) return null;const sock=await tryConnect(order[index]);return sock||(await tryNext(index+1));};
    if(mode==="s5"){if(proxyCfg){const sock=await tryConnect("s5");if(sock){setRemote(sock);await connectStreams(sock,ws,header,null,userCfg);}}return;}
    const primary=await tryConnect(order[0]);
    if(!primary){const backup=await tryNext(1);if(backup){setRemote(backup);await connectStreams(backup,ws,header,null,userCfg);}return;}
    setRemote(primary);
    const retryFunc=order.length>1?async()=>{const backup=await tryNext(1);if(backup){try{primary.close();}catch{}setRemote(backup);await connectStreams(backup,ws,header,null,userCfg);}}:null;
    await connectStreams(primary,ws,header,retryFunc,userCfg);
};

export default {
    async fetch(req, env) {

        const buildPath = (t, d, s, p) => {
            const params = [];
            if (t) params.push(`${getParam("t")}=${t}`);
            if (d) params.push(`${getParam("d")}=1`);
            if (s) params.push(`${getParam("s")}=${encodeURIComponent(s)}`);
            if (p) params.push(`${getParam("p")}=${encodeURIComponent(p)}`);
            params.push(`${getParam("v")}=${randStr()}`);
            return `${getPath()}?${params.join("&")}`;
        };

        const buildVlessUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port, echParam = "") =>
            `vless://${uuid}@${preferredDomain}:${port}?encryption=none&security=tls&sni=${workerHost}&type=ws${echParam}&host=${workerHost}&path=${encodeURIComponent(rawPathQuery)}&fp=chrome#${encodeURIComponent(label || preferredDomain)}`;
        const buildTrojanUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port, echParam = "") =>
            `trojan://${uuid}@${preferredDomain}:${port}?security=tls&sni=${workerHost}&type=ws${echParam}&host=${workerHost}&path=${encodeURIComponent(rawPathQuery)}#${encodeURIComponent(label || preferredDomain)}`;

        const buildVariants = (s5, proxyIp, nodeTypes) => {
            const v = [];
            const types = Array.isArray(nodeTypes) && nodeTypes.length > 0 ? nodeTypes : ["direct"];
            const proxyLabel = s5 ? proxyTypeLabel(s5) : "";
            if (types.includes("direct")) {
                v.push({ label: "直连", raw: buildPath("d", 1, null, null) });
            }
            if (s5 && types.includes("s5")) {
                v.push({ label: proxyLabel, raw: buildPath("s", null, s5, null) });
            }
            if (s5 && types.includes("direct_s5")) {
                v.push({ label: "直连+" + proxyLabel, raw: buildPath("p", 1, s5, null) });
            }
            if (proxyIp && types.includes("direct_proxy")) {
                v.push({ label: "直连+ProxyIP", raw: buildPath("p", 1, null, proxyIp) });
            }
            if (s5 && proxyIp && types.includes("direct_s5_proxy")) {
                v.push({ label: "直连+" + proxyLabel + "+ProxyIP", raw: buildPath("p", 1, s5, proxyIp) });
            }
            if (v.length === 0) {
                v.push({ label: "直连", raw: buildPath("d", 1, null, null) });
            }
            return v;
        };

        const getDomainPortLists = (request, cfg) => {
            const workerHost = new URL(request.url).hostname;
            const domains = [
                ...new Map(
                    (cfg.domains || []).filter((x) => x && x.ip).map((x) => [x.ip, x]),
                ).values(),
            ];
            if (!domains.length)
                domains.push({ ip: (cfg.domain || workerHost).trim() || workerHost, remark: "" });
            const ports = [
                ...new Set(
                    (cfg.ports || [])
                        .concat(cfg.port || [])
                        .map((p) => Math.max(1, Math.min(65535, +p || 443))),
                ),
            ];
            if (!ports.length) ports.push(443);
            return { workerHost, domains, ports };
        };

        if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
            const u = new URL(req.url);
            const userConfig = await getUserConfig(env);
            const [client, ws] = Object.values(new WebSocketPair());
            ws.accept();
            ws.binaryType = 'arraybuffer';

            if (u.pathname.includes("%3F")) {
                const decoded = decodeURIComponent(u.pathname);
                const queryIndex = decoded.indexOf("?");
                if (queryIndex !== -1) {
                    u.search = decoded.slice(queryIndex);
                    u.pathname = decoded.slice(0, queryIndex);
                }
            }

            const getParamValue = (keys) => {
                for (const k of keys) {
                    const v = u.searchParams.get(k);
                    if (v !== null) return v;
                }
                return null;
            };
            const modeMap = { d: "direct", s: "s5", p: "parallel" };
            const modeVal = getParamValue(["t", "m", "type", "mode"]);
            const mode = modeMap[modeVal] || "parallel";
            const s5Param = getParamValue(["s", "socks", "proxy"]);
            const proxyParam = getParamValue(["p", "ip", "proxyip"]);
            let proxyConfig = s5Param ? parseProxyAddress(s5Param) : null;
            if (!proxyConfig && s5Param) {
                const path = s5Param;
                if (path.includes("@")) {
                    const [cred, server] = path.split("@"),
                        [user, pass] = cred.split(":"),
                        [host, port] = server.split(":");
                    if (host && port)
                        proxyConfig = {
                            type: "socks5",
                            host,
                            port: +port,
                            username: user,
                            password: pass,
                        };
                } else if (path.includes(":")) {
                    const [host, port] = path.split(":");
                    if (host && port)
                        proxyConfig = {
                            type: "socks5",
                            host,
                            port: +port,
                            username: "",
                            password: "",
                        };
                }
            }
            const PROXY_IP = proxyParam ? String(proxyParam) : null;

            const getOrder = () => {
                if (mode === "s5") return ["s5"];
                const order = [];
                const params = u.search.slice(1).split("&");
                for (const pair of params) {
                    const key = pair.split("=")[0];
                    if (["d", "dir", "direct"].includes(key)) order.push("direct");
                    if (["s", "socks", "proxy"].includes(key)) order.push("s5");
                    if (["p", "ip", "proxyip"].includes(key)) order.push("proxy");
                }
                if (order.length === 0 && PROXY_IP) return ["proxy", "direct"];
                return order.length ? order : ["direct"];
            };

            let remote = null,
                udpWriter = null,
                isDNS = false,
                isTrojan = false,
                trojanUDPCtx = null;

            const setRemote = (val) => (remote = val);

            const processTrojanUDP = async (chunk) => {
                if (!trojanUDPCtx) {
                    trojanUDPCtx = { cache: new Uint8Array(0) };
                }
                const curr = new Uint8Array(chunk);
                const input = trojanUDPCtx.cache.byteLength
                    ? new Uint8Array([...trojanUDPCtx.cache, ...curr])
                    : curr;

                let cursor = 0;
                while (cursor < input.byteLength) {
                    const at = input[cursor];
                    let ac = cursor + 1;
                    let al = 0;

                    if (at === 1) {
                        al = 4;
                    } else if (at === 4) {
                        al = 16;
                    } else if (at === 3) {
                        if (input.byteLength < ac + 1) break;
                        al = 1 + input[ac];
                    } else {
                        break;
                    }

                    const pc = ac + al;
                    if (input.byteLength < pc + 6) break;

                    const port = (input[pc] << 8) | input[pc + 1];
                    const pl = (input[pc + 2] << 8) | input[pc + 3];

                    if (input[pc + 4] !== 0x0d || input[pc + 5] !== 0x0a) break;

                    const ps = pc + 6;
                    const pe = ps + pl;
                    if (input.byteLength < pe) break;

                    const ah = input.slice(cursor, pc + 2);
                    const payload = input.slice(ps, pe);
                    cursor = pe;

                    if (port !== 53) continue;

                    let q = payload;
                    if (
                        payload.byteLength < 2 ||
                        ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2
                    ) {
                        q = new Uint8Array(payload.byteLength + 2);
                        q[0] = (payload.byteLength >>> 8) & 0xff;
                        q[1] = payload.byteLength & 0xff;
                        q.set(payload, 2);
                    }

                    const rc = { cache: new Uint8Array(0) };
                    const ts = new TransformStream({
                        transform(c, ctrl) {
                            const cr = new Uint8Array(c);
                            const ir = rc.cache.byteLength
                                ? new Uint8Array([...rc.cache, ...cr])
                                : cr;

                            let rcursor = 0;
                            while (rcursor + 2 <= ir.byteLength) {
                                const dl = (ir[rcursor] << 8) | ir[rcursor + 1];
                                const ds = rcursor + 2;
                                const de = ds + dl;

                                if (de > ir.byteLength) break;

                                const dp = ir.slice(ds, de);
                                const f = new Uint8Array(ah.byteLength + 4 + dp.byteLength);

                                f.set(ah, 0);
                                f[ah.byteLength] = (dp.byteLength >>> 8) & 0xff;
                                f[ah.byteLength + 1] = dp.byteLength & 0xff;
                                f[ah.byteLength + 2] = 0x0d;
                                f[ah.byteLength + 3] = 0x0a;
                                f.set(dp, ah.byteLength + 4);

                                ctrl.enqueue(f);
                                rcursor = de;
                            }
                            rc.cache = ir.slice(rcursor);
                        },
                    });

                    ts.readable.pipeTo(
                        new WritableStream({
                            async write(r) {
                                if (ws.readyState === 1) {
                                    ws.send(r);
                                }
                            },
                        }),
                    );

                    const w = ts.writable.getWriter();
                    try {
                        const resp = await fetch("https://1.1.1.1/dns-query", {
                            method: "POST",
                            headers: { "content-type": "application/dns-message" },
                            body: q,
                        });
                        await w.write(await resp.arrayBuffer());
                    } catch {}

                    w.releaseLock();
                }
                trojanUDPCtx.cache = input.slice(cursor);
            };

            new ReadableStream({
                start(ctrl) {
                    ws.addEventListener("message", (e) => ctrl.enqueue(e.data));
                    ws.addEventListener("close", () => {
                        remote?.close();
                        ctrl.close();
                    });
                    ws.addEventListener("error", () => {
                        remote?.close();
                        ctrl.error();
                    });
                    const early = req.headers.get("sec-websocket-protocol");
                    if (early) {
                        try {
                            const processed = early.replace(/-/g, "+").replace(/_/g, "/");
                            ctrl.enqueue(
                                Uint8Array.from(atob(processed), (c) => c.charCodeAt(0)).buffer,
                            );
                        } catch {}
                    }
                },
            })
                .pipeTo(
                    new WritableStream({
                        async write(data) {
                            if (isTrojan && isDNS) return processTrojanUDP(data);
                            if (isDNS) return udpWriter?.write(data);
                            if (remote) {
                                const w = remote.writable.getWriter();
                                await w.write(data);
                                w.releaseLock();
                                return;
                            }
                            if (data.byteLength >= 58) {
                                const trojanResult = parseTrojanRequest(data, userConfig.uuid);
                                if (!trojanResult.hasError) {
                                    isTrojan = true;
                                    const { hostname, port, isUDP, rawClientData } = trojanResult;
                                    if (isUDP) {
                                        if (port !== 53) return;
                                        isDNS = true;
                                        if (rawClientData.byteLength)
                                            await processTrojanUDP(rawClientData);
                                        return;
                                    }
                                    const trojanConnectStreams = async (remoteSock, webSocket) => {
                                        remoteSock.readable
                                            .pipeTo(
                                                new WritableStream({
                                                    async write(chunk) {
                                                        if (webSocket.readyState === 1)
                                                            webSocket.send(chunk);
                                                    },
                                                    abort() {},
                                                }),
                                            )
                                            .catch(() => {});
                                    };
                                    const tryConnect = async (type) => {
                                        try {
                                            if (type === "direct")
                                                return await connectDirect(
                                                    hostname,
                                                    port,
                                                    rawClientData,
                                                );
                                            if (type === "s5" && proxyConfig)
                                                return await connectViaProxy(
                                                    proxyConfig,
                                                    hostname,
                                                    port,
                                                    rawClientData,
                                                );
                                            if (type === "proxy" && PROXY_IP) {
                                                const [ph, pp = port] = PROXY_IP.split(":");
                                                return await connectDirect(
                                                    ph,
                                                    +pp || port,
                                                    rawClientData,
                                                );
                                            }
                                        } catch {}
                                        return null;
                                    };
                                    const order = getOrder();
                                    const tryNext = async (index) => {
                                        if (index >= order.length) return null;
                                        const sock = await tryConnect(order[index]);
                                        return sock || (await tryNext(index + 1));
                                    };
                                    if (mode === "s5" && proxyConfig) {
                                        const sock = await tryConnect("s5");
                                        if (sock) {
                                            remote = sock;
                                            await trojanConnectStreams(sock, ws);
                                        }
                                        return;
                                    }
                                    const primary = await tryConnect(order[0]);
                                    if (!primary) {
                                        const backup = await tryNext(1);
                                        if (backup) {
                                            remote = backup;
                                            await trojanConnectStreams(backup, ws);
                                        }
                                        return;
                                    }
                                    remote = primary;
                                    await trojanConnectStreams(primary, ws);
                                    return;
                                }
                            }
                            if (data.byteLength < 24) return;
                            const uuidBytes = new Uint8Array(data.slice(1, 17));
                            const expectedUUID = userConfig.uuid.replace(/-/g, "");
                            for (let i = 0; i < 16; i++) {
                                if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16))
                                    return;
                            }
                            const view = new DataView(data);
                            const optLen = view.getUint8(17);
                            const cmd = view.getUint8(18 + optLen);
                            if (cmd !== 1 && cmd !== 2) return;
                            let pos = 19 + optLen;
                            const port = view.getUint16(pos);
                            const type = view.getUint8(pos + 2);
                            pos += 3;
                            let addr = "";
                            if (type === 1) {
                                addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
                                pos += 4;
                            } else if (type === 2) {
                                const len = view.getUint8(pos++);
                                addr = new TextDecoder().decode(data.slice(pos, pos + len));
                                pos += len;
                            } else if (type === 3) {
                                const ipv6 = [];
                                for (let i = 0; i < 8; i++, pos += 2)
                                    ipv6.push(view.getUint16(pos).toString(16));
                                addr = ipv6.join(":");
                            } else return;
                            const header = new Uint8Array([data[0], 0]);
                            const payload = data.slice(pos);
                            if (cmd === 2) {
                                if (port !== 53) return;
                                isDNS = true;
                                let sent = false;
                                const { readable, writable } = new TransformStream({
                                    transform(chunk, ctrl) {
                                        for (let i = 0; i < chunk.byteLength; ) {
                                            const len = new DataView(
                                                chunk.slice(i, i + 2),
                                            ).getUint16(0);
                                            ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                                            i += 2 + len;
                                        }
                                    },
                                });
                                readable.pipeTo(
                                    new WritableStream({
                                        async write(query) {
                                            try {
                                                const resp = await fetch(
                                                    "https://1.1.1.1/dns-query",
                                                    {
                                                        method: "POST",
                                                        headers: {
                                                            "content-type":
                                                                "application/dns-message",
                                                        },
                                                        body: query,
                                                    },
                                                );
                                                if (ws.readyState === 1) {
                                                    const result = new Uint8Array(
                                                        await resp.arrayBuffer(),
                                                    );
                                                    ws.send(
                                                        new Uint8Array([
                                                            ...(sent ? [] : header),
                                                            result.length >> 8,
                                                            result.length & 0xff,
                                                            ...result,
                                                        ]),
                                                    );
                                                    sent = true;
                                                }
                                            } catch {}
                                        },
                                    }),
                                );
                                udpWriter = writable.getWriter();
                                return udpWriter.write(payload);
                            }
                            await connectParallel(
                                addr,
                                port,
                                payload,
                                getOrder(),
                                mode,
                                proxyConfig,
                                PROXY_IP,
                                getOrder,
                                connectViaProxy,
                                ws,
                                header,
                                userConfig,
                                remote,
                                setRemote,
                                null,
                            );
                        },
                    }),
                )
                .catch(() => {});

            return new Response(null, { status: 101, webSocket: client });
        }

        const url = new URL(req.url);

        if (url.pathname === "/api/fetch-best-ip") {
            const userConfig = await getUserConfig(env);
            let apiUrl = userConfig.bestIpApi || DEFAULT_BEST_IP_API;
            let bodyUUID = null;
            try {
                const body = await req.json();
                if (body.apiUrl) apiUrl = body.apiUrl;
                bodyUUID = body.uuid || null;
            } catch {}
            // body.uuid 或 cookie session 任一有效即可
            const validUUID = bodyUUID || getSessionUUID(req);
            if (!validUUID) return json({ error: "请先登录" }, 401);
            if (validUUID !== userConfig.uuid) return json({ error: "UUID错误，无权访问" }, 403);
            
            try {
                const response = await fetch(apiUrl, {
                    headers: {
                        "Accept": "text/html,application/xhtml+xml,application/xml;",
                        "User-Agent": "cmliu/CF-Workers-DD2D",
                    },
                });
                if (!response.ok) {
                    throw new Error(`API请求失败: ${response.status}`);
                }
                const text = await response.text();
                const ips = text
                    .split(/[\n\r,]+/)
                    .map((ip) => ip.trim())
                    .filter((ip) => {
                        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^:(?::[0-9a-fA-F]{1,4}){1,7}$/;
                        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
                    });
                return json({ success: true, ips: ips });
            } catch (error) {
                return json({ success: false, error: error.message }, 500);
            }
        }

        if (url.pathname === "/api/config") {
            const userConfig = await getUserConfig(env);
            if (req.method === "GET") {
                const inputUUID = getSessionUUID(req, url);
                if (!inputUUID) return json({ error: "请先登录" }, 401);
                if (inputUUID !== userConfig.uuid) return json({ error: "UUID错误，无权访问" }, 403);
                return json(userConfig);
            } else if (req.method === "POST") {
                try {
                    const incoming = await req.json();
                    if (!incoming.uuid || typeof incoming.uuid !== "string")
                        return json({ error: "UUID不能为空" }, 400);
                    if (incoming.uuid !== userConfig.uuid)
                        return json({ error: "UUID错误，无权访问" }, 403);
                    if (typeof incoming.subLinkBase === "string" &&
                        incoming.subLinkBase.trim() &&
                        !normalizeSubLinkBase(incoming.subLinkBase))
                        return json({ error: "订阅转换服务地址格式不正确，需是 http(s):// 开头的服务地址（不要带 ? 参数）" }, 400);
                    let domains = Array.isArray(incoming.domains)
                        ? incoming.domains
                              .map((x) => {
                                  if (typeof x === "object" && x !== null) {
                                      return {
                                          ip: (x.ip || "").trim(),
                                          remark: (x.remark || "").trim(),
                                      };
                                  } else if (typeof x === "string") {
                                      return { ip: x.trim(), remark: "" };
                                  }
                                  return null;
                              })
                              .filter((x) => x && x.ip)
                        : [];
                    if (incoming.domain) {
                        const d = (incoming.domain + "").trim();
                        if (d && !domains.some((x) => x.ip === d))
                            domains.unshift({ ip: d, remark: "" });
                    }
                    let ports = Array.isArray(incoming.ports)
                        ? incoming.ports.map((x) =>
                              Math.max(1, Math.min(65535, parseInt(x + "", 10) || 443)),
                          )
                        : [];
                    if (incoming.port) {
                        const pn = Math.max(
                            1,
                            Math.min(65535, parseInt(incoming.port + "", 10) || 443),
                        );
                        if (!ports.includes(pn)) ports.unshift(pn);
                    }
                    const fallbackTimeout =
                        typeof incoming.fallbackTimeout === "number"
                            ? Math.max(1, Math.min(5000, incoming.fallbackTimeout))
                            : 100;
                    const uniqueIps = new Set();
                    domains = domains.filter((x) => {
                        if (uniqueIps.has(x.ip)) return false;
                        uniqueIps.add(x.ip);
                        return true;
                    });
                    ports = [...new Set(ports)];
                    if (!domains.length) domains.push({ ip: "", remark: "" });
                    if (!ports.length) ports.push(443);
                    const normalized = {
                        uuid: incoming.uuid,
                        domain: domains[0]?.ip || "",
                        port: String(ports[0] || 443),
                        s5: incoming.s5 || "",
                        proxyIp: incoming.proxyIp || "",
                        domains: domains,
                        ports: ports,
                        fallbackTimeout,
                        subLinkBase: normalizeSubLinkBase(incoming.subLinkBase) || DEFAULT_SUBLINK_BASE,
                        bestIpApi: incoming.bestIpApi || DEFAULT_BEST_IP_API,
                        autoUpdateBestIp: !!incoming.autoUpdateBestIp,
                        nodeTypes: Array.isArray(incoming.nodeTypes) && incoming.nodeTypes.length > 0
                            ? incoming.nodeTypes
                            : ["direct"],
                        protocols: Array.isArray(incoming.protocols) && incoming.protocols.length > 0
                            ? incoming.protocols
                            : ["vless", "trojan"],
                        ech: !!incoming.ech,
                        echConfig: {
                            sni: (typeof incoming.echConfig?.sni === "string" ? incoming.echConfig.sni.trim() : "") || DEFAULT_ECH_SNI,
                            dns: (typeof incoming.echConfig?.dns === "string" ? incoming.echConfig.dns.trim() : "") || DEFAULT_ECH_DNS,
                        },
                    };
                    if (env.VTPanel)
                        await env.VTPanel.put("user_config", JSON.stringify(normalized));
                    return json({ success: true, message: "配置保存成功" });
                } catch {
                    return json({ error: "配置保存失败" }, 500);
                }
            }
        }

        if (url.pathname === "/sub") {
            const inputUUID = getSessionUUID(req, url);
            if (!inputUUID) return new Response("missing uuid", { status: 400 });
            const userConfig = await getUserConfig(env);
            if (inputUUID !== userConfig.uuid) return new Response("Not Found", { status: 404 });
            const { workerHost, domains, ports } = getDomainPortLists(req, userConfig);
            const variants = buildVariants(userConfig.s5, userConfig.proxyIp, userConfig.nodeTypes);
            const ua = (req.headers.get("User-Agent") || "").toLowerCase();
            const isSubConverterRequest =
                url.searchParams.has("b64") ||
                url.searchParams.has("base64") ||
                req.headers.get("subconverter-request") ||
                req.headers.get("subconverter-version") ||
                ua.includes("subconverter");
            let 订阅类型 = isSubConverterRequest
                ? "mixed"
                : url.searchParams.has("target")
                  ? url.searchParams.get("target")
                  : url.searchParams.has("clash") ||
                      ua.includes("clash") ||
                      ua.includes("meta") ||
                      ua.includes("mihomo")
                    ? "clash"
                    : url.searchParams.has("sb") ||
                        url.searchParams.has("singbox") ||
                        ua.includes("singbox") ||
                        ua.includes("sing-box")
                      ? "singbox"
                      : url.searchParams.has("surge") || ua.includes("surge")
                        ? "surge&ver=4"
                        : url.searchParams.has("quanx") || ua.includes("quantumult")
                          ? "quanx"
                          : url.searchParams.has("loon") || ua.includes("loon")
                            ? "loon"
                            : "mixed";
            const out = [];
            const protocols = Array.isArray(userConfig.protocols) && userConfig.protocols.length > 0
                ? userConfig.protocols
                : ["vless", "trojan"];
            const echParam = buildEchParam(userConfig);
            // 收集所有节点使用的域名（排除纯 IP），用于 ECH nameserver-policy 走 DoH 解析
            const isIP = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-fA-F:]+$/.test(s);
            const echHosts = [...new Set(
                [workerHost, ...domains.map((d) => d.ip)]
                    .filter((h) => h && !isIP(h)),
            )];
            const echSni = userConfig.echConfig?.sni || "";
            const echDns = userConfig.echConfig?.dns || "";
            for (const d of domains) {
                for (const p of ports) {
                    for (const v of variants) {
                        if (protocols.includes("vless")) {
                            const vlessName = d.remark ? `V ${v.label} ${d.remark}` : `V ${v.label} ${d.ip}:${p}`;
                            out.push(
                                buildVlessUri(v.raw, userConfig.uuid, vlessName, workerHost, d.ip, p, echParam),
                            );
                        }
                        if (protocols.includes("trojan")) {
                            const trojanName = d.remark
                                ? `T ${v.label} ${d.remark}`
                                : `T ${v.label}  ${d.ip}:${p}`;
                            out.push(
                                buildTrojanUri(
                                    v.raw,
                                    userConfig.uuid,
                                    trojanName,
                                    workerHost,
                                    d.ip,
                                    p,
                                    echParam,
                                ),
                            );
                        }
                    }
                }
            }
            const nodesContent = out.join("\n");
            const responseHeaders = {
                "content-type": "text/plain; charset=utf-8",
                "Profile-Update-Interval": "3",
                "Profile-web-page-url": new URL(req.url).origin + "/",
                "Cache-Control": "no-store",
            };
            const encodedNodes = b64e(nodesContent);
            // "surge&ver=4" 这类带参数的 target 先按 & 截断再取端点
            const 端点名 = String(订阅类型).split("&")[0].trim().toLowerCase();
            const endpoint = SUBLINK_TARGET_ENDPOINTS[端点名];
            // mixed，以及 Sublink 不支持的格式（quanx / loon 等）：直接返回通用 base64 节点列表
            if (!endpoint) {
                return new Response(encodedNodes + "\n", {
                    status: 200,
                    headers: responseHeaders,
                });
            }
            // 转换服务地址已在 getUserConfig 里归一化（面板配置 > 环境变量 SUBLINK_BASE > 内置默认值）
            const sublinkBase = normalizeSubLinkBase(userConfig.subLinkBase) || DEFAULT_SUBLINK_BASE;
            const 订阅转换URL = `${sublinkBase}/${endpoint}?config=${encodeURIComponent(encodedNodes)}`;
            // 透传客户端 UA：Sublink 会据此选择 sing-box 配置档位（1.11 / 1.12 / 1.14），
            // 用固定的假 UA 会让老版本 sing-box 拿到不兼容的配置。
            const clientUA = req.headers.get("User-Agent") || "";
            const convertUA = /^[\x20-\x7e]{1,200}$/.test(clientUA) ? clientUA : `Sublink/${endpoint}`;
            try {
                const response = await fetch(订阅转换URL, {
                    headers: { "User-Agent": convertUA, Accept: "*/*" },
                });
                if (response.ok) {
                    let 转换后内容 = await response.text();
                    // ECH 热补丁：订阅转换后 ECH 信息丢失，需在返回前补回
                    if (userConfig.ech && endpoint === "clash") {
                        转换后内容 = clashEchHotPatch(转换后内容, {
                            uuid: userConfig.uuid,
                            echSni,
                            echDns,
                            hosts: echHosts,
                        });
                        responseHeaders["content-type"] = "application/x-yaml; charset=utf-8";
                    } else if (userConfig.ech && endpoint === "singbox") {
                        转换后内容 = singboxEchHotPatch(转换后内容, {
                            uuid: userConfig.uuid,
                            echSni,
                        });
                        responseHeaders["content-type"] = "application/json; charset=utf-8";
                    } else {
                        if (endpoint === "clash")
                            responseHeaders["content-type"] = "application/x-yaml; charset=utf-8";
                        else if (endpoint === "singbox")
                            responseHeaders["content-type"] = "application/json; charset=utf-8";
                    }
                    return new Response(转换后内容, { status: 200, headers: responseHeaders });
                } else {
                    const errorText = await response.text().catch(() => "");
                    return text(
                        "订阅转换失败: " +
                            response.status +
                            " " +
                            response.statusText +
                            "\n" +
                            errorText +
                            "\nURL: " +
                            订阅转换URL,
                        500,
                    );
                }
            } catch {
                return new Response(encodedNodes + "\n", {
                    status: 200,
                    headers: responseHeaders,
                });
            }
        }

        if (url.pathname === "/" || url.pathname === "/index.html") {
            const userConfig = await getUserConfig(env);
            let pwd = url.searchParams.get("pwd");
            let isLoggedIn = false;
            let cookieSetHeader = null;
            let errorMsg = "";

            // 处理 POST 登录请求（支持浏览器保存密码）
            if (req.method === "POST") {
                try {
                    const formData = await req.formData();
                    pwd = formData.get("pwd");
                } catch {}
                if (pwd && pwd === userConfig.uuid) {
                    return new Response(null, {
                        status: 303,
                        headers: {
                            "Location": url.origin + url.pathname,
                            "Set-Cookie": SESSION_COOKIE(pwd),
                        },
                    });
                } else {
                    errorMsg = "UUID错误，请检查后重新输入";
                }
            } else if (pwd) {
                // GET 方式带 pwd 参数（兼容旧方式）
                if (pwd === userConfig.uuid) {
                    isLoggedIn = true;
                    cookieSetHeader = SESSION_COOKIE(pwd);
                } else {
                    errorMsg = "UUID错误，请检查后重新输入";
                }
            } else {
                const cookieUUID = getSessionUUID(req);
                if (cookieUUID === userConfig.uuid) isLoggedIn = true;
            }

            if (!isLoggedIn) {
            const html = `
<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>ZQ-VTPanel</title>
	<link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/04/21/489658.webp">
	<style>
		:root {
		    --primary: #2563eb;
		    --primary-light: #3b82f6;
		    --primary-dark: #1d4ed8;
		    --bg-gradient-start: #eff6ff;
		    --bg-gradient-end: #dbeafe;
		    --card-bg: rgba(255,255,255,0.95);
		    --text-primary: #1e3a5f;
		    --text-secondary: #64748b;
		    --border-color: #bfdbfe;
		    --shadow: 0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);
		    --shadow-lg: 0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1);
		}
		* { box-sizing: border-box; }
		body {
		    font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
		    margin: 0;
		    min-height: 100vh;
		    background: linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);
		    color: var(--text-primary);
		    line-height: 1.6;
		    display: flex;
		    align-items: center;
		    justify-content: center;
		}
		.card {
		    background: var(--card-bg);
		    border-radius: 20px;
		    padding: 32px;
		    box-shadow: var(--shadow-lg);
		    border: 1px solid var(--border-color);
		    max-width: 500px;
		    width: 90%;
		    backdrop-filter: blur(10px);
		}
		h1 {
		    margin: 0 0 24px;
		    font-size: 28px;
		    font-weight: 700;
		    text-align: center;
		    background: linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
		    -webkit-background-clip: text;
		    -webkit-text-fill-color: transparent;
		    background-clip: text;
		}
		.form-group { margin-bottom: 20px; }
		label {
		    display: block;
		    margin-bottom: 8px;
		    font-weight: 600;
		    color: var(--text-primary);
		}
		input[type="text"], input[type="password"] {
		    width: 100%;
		    padding: 14px;
		    border: 2px solid var(--border-color);
		    border-radius: 12px;
		    background: rgba(255,255,255,0.8);
		    color: var(--text-primary);
		    font-size: 16px;
		    box-sizing: border-box;
		    transition: all .3s ease;
		}
		input[type="text"]:focus, input[type="password"]:focus {
		    outline: none;
		    border-color: var(--primary);
		    box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
		}
		button {
		    width: 100%;
		    background: linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);
		    color: #fff;
		    border: none;
		    border-radius: 12px;
		    padding: 14px;
		    font-size: 16px;
		    font-weight: 600;
		    cursor: pointer;
		    transition: all .3s ease;
		    box-shadow: var(--shadow);
		}
		button:hover {
		    background: linear-gradient(135deg,var(--primary-dark) 0%,var(--primary) 100%);
		    transform: translateY(-2px);
		    box-shadow: var(--shadow-lg);
		}
		.error {
		    margin-top: 16px;
		    color: #dc2626;
		    text-align: center;
		    font-size: 14px;
		    padding: 12px;
		    border-radius: 8px;
		    background: rgba(220,38,38,0.1);
		    border: 1px solid rgba(220,38,38,0.2);
		}
	</style>
</head>
<body>
	<div class="card">
		<h1>ZQ-VTPanel</h1>
		<form method="post" action="/">
			<div class="form-group">
				<label for="pwd">请输入UUID</label>
				<input type="password" id="pwd" name="pwd" required placeholder="请输入正确的UUID" autocomplete="current-password">
			</div>
			<button type="submit">进入节点界面</button>
		</form>
		${errorMsg ? `<div class="error">${errorMsg}</div>` : ''}
	</div>
</body>
</html>`;
                return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
            }

            // ---------- 已登录，渲染面板 ----------
            const userUUID = userConfig.uuid;
            const origin = new URL(req.url).origin;
            const subUrl = `${origin}/sub?pwd=${userUUID}`;
            const lists = getDomainPortLists(req, userConfig);
            const variants = buildVariants(userConfig.s5, userConfig.proxyIp, userConfig.nodeTypes);
            const allNodeUris = [];
            const protocols = Array.isArray(userConfig.protocols) && userConfig.protocols.length > 0
                ? userConfig.protocols
                : ["vless", "trojan"];
            const echParam = buildEchParam(userConfig);
            for (const d of lists.domains) {
                for (const p of lists.ports) {
                    for (const v of variants) {
                        if (protocols.includes("vless")) {
                            const vlessName = d.remark ? `V ${v.label} ${d.remark}` : `V ${v.label} ${d.ip}:${p}`;
                            allNodeUris.push(
                                buildVlessUri(v.raw, userUUID, vlessName, lists.workerHost, d.ip, p, echParam),
                            );
                        }
                        if (protocols.includes("trojan")) {
                            const trojanName = d.remark
                                ? `T ${v.label} ${d.remark}`
                                : `T ${v.label}  ${d.ip}:${p}`;
                            allNodeUris.push(
                                buildTrojanUri(
                                    v.raw,
                                    userUUID,
                                    trojanName,
                                    lists.workerHost,
                                    d.ip,
                                    p,
                                    echParam,
                                ),
                            );
                        }
                    }
                }
            }
            const allNodesJson = JSON.stringify(allNodeUris);
            const html = `
<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>ZQ-VTPanel</title>
	<link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/04/21/489658.webp">
	<style>
		:root {
		  --primary: #2563eb;
		  --primary-light: #3b82f6;
		  --primary-dark: #1d4ed8;
		  --bg-gradient-start: #eff6ff;
		  --bg-gradient-end: #dbeafe;
		  --card-bg: rgba(255, 255, 255, 0.95);
		  --text-primary: #1e3a5f;
		  --text-secondary: #64748b;
		  --border-color: #bfdbfe;
		  --shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.1), 0 2px 4px -1px rgba(37, 99, 235, 0.06);
		  --shadow-lg: 0 20px 25px -5px rgba(37, 99, 235, 0.15), 0 10px 10px -5px rgba(37, 99, 235, 0.1);
		}
		
		* {
		  box-sizing: border-box;
		}
		
		body {
		  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
		  margin: 0;
		  min-height: 100vh;
		  background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
		  color: var(--text-primary);
		  line-height: 1.6;
		}
		
		.wrap {
		  max-width: 1000px;
		  margin: 0 auto;
		  padding: 32px 24px;
		  position: relative;
		}
		
		.header {
		  text-align: center;
		  margin-bottom: 32px;
		  padding: 24px 0;
		  border-bottom: 2px solid var(--border-color);
		}
		
		h1 {
		  margin: 0;
		  font-size: 32px;
		  font-weight: 700;
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  -webkit-background-clip: text;
		  -webkit-text-fill-color: transparent;
		  background-clip: text;
		}
		
		.subtitle {
		  color: var(--text-secondary);
		  margin-top: 8px;
		  font-size: 14px;
		}
		
		.topbar {
		  position: absolute;
		  right: 24px;
		  top: 32px;
		  display: flex;
		  gap: 12px;
		}
		
		.topbar a {
		  width: 42px;
		  height: 42px;
		  border-radius: 12px;
		  background: var(--card-bg);
		  border: 1px solid var(--border-color);
		  color: var(--primary);
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  transition: all .3s ease;
		  box-shadow: var(--shadow);
		}
		
		.topbar a:hover {
		  background: var(--primary);
		  color: #fff;
		  transform: translateY(-2px);
		  box-shadow: var(--shadow-lg);
		}
		
		.main-card {
		  background: var(--card-bg);
		  border-radius: 20px;
		  padding: 28px;
		  margin-bottom: 24px;
		  box-shadow: var(--shadow-lg);
		  border: 1px solid var(--border-color);
		  backdrop-filter: blur(10px);
		}
		
		.section-title {
		  font-size: 18px;
		  font-weight: 600;
		  color: var(--primary);
		  margin-bottom: 16px;
		  display: flex;
		  align-items: center;
		  gap: 8px;
		}
		
		.section-title::before {
		  content: '';
		  width: 4px;
		  height: 20px;
		  background: linear-gradient(180deg, var(--primary) 0%, var(--primary-light) 100%);
		  border-radius: 2px;
		}
		
		.url-box {
		  background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
		  border: 2px solid var(--border-color);
		  border-radius: 12px;
		  padding: 16px;
		  font-family: 'Monaco', 'Consolas', monospace;
		  font-size: 13px;
		  color: var(--text-primary);
		  word-break: break-all;
		  position: relative;
		  overflow: hidden;
		}
		
		.url-box::before {
		  content: '';
		  position: absolute;
		  top: 0;
		  left: 0;
		  right: 0;
		  height: 3px;
		  background: linear-gradient(90deg, var(--primary) 0%, var(--primary-light) 100%);
		}
		
		.button-group {
		  display: flex;
		  gap: 12px;
		  margin-top: 20px;
		  flex-wrap: wrap;
		}
		
		.btn {
		  flex: 1;
		  min-width: 120px;
		  padding: 12px 20px;
		  border-radius: 10px;
		  border: none;
		  font-size: 14px;
		  font-weight: 600;
		  cursor: pointer;
		  transition: all .3s ease;
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  gap: 6px;
		}
		
		.btn-primary {
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  color: #fff;
		  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
		}
		
		.btn-primary:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4);
		}
		
		.btn-secondary {
		  background: #fff;
		  color: var(--primary);
		  border: 2px solid var(--border-color);
		}
		
		.btn-secondary:hover {
		  transform: translateY(-2px);
		  box-shadow: var(--shadow-lg);
		}
		
		.btn-success {
		  background: linear-gradient(135deg, #10b981 0%, #34d399 100%);
		  color: #fff;
		  box-shadow: 0 4px 14px rgba(16, 185, 129, 0.3);
		}
		
		.btn-success:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
		}
		
		.btn-danger {
		  background: linear-gradient(135deg, #ef4444 0%, #f87171 100%);
		  color: #fff;
		}
		
		.btn-danger:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
		}
		
		.form-group {
		  margin-bottom: 20px;
		}
		
		label {
		  display: block;
		  margin-bottom: 8px;
		  font-weight: 600;
		  color: var(--text-primary);
		}
		
		input[type="text"],
		input[type="number"] {
		  width: 100%;
		  padding: 12px 16px;
		  border: 2px solid var(--border-color);
		  border-radius: 10px;
		  background: #fff;
		  color: var(--text-primary);
		  font-size: 14px;
		  box-sizing: border-box;
		  transition: all .3s ease;
		}
		
		input[type="text"]:focus,
		input[type="number"]:focus {
		  outline: none;
		  border-color: var(--primary);
		  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
		}
		
		.input-group {
		  display: flex;
		  gap: 8px;
		}
		
		.input-group input {
		  flex: 1;
		}
		
		.input-group .btn {
		  flex: none;
		  min-width: auto;
		  padding: 10px 16px;
		  font-size: 13px;
		}
		
		.list {
		  display: flex;
		  flex-direction: column;
		  gap: 8px;
		  margin-bottom: 12px;
		}
		
		.list-item {
		  display: flex;
		  gap: 8px;
		  align-items: center;
		}
		
		.list-item input {
		  flex: 1;
		}
		
		.list-item .btn {
		  flex: none;
		  min-width: auto;
		  padding: 8px 12px;
		  font-size: 12px;
		}
		
		.chip {
		  padding: 6px 14px;
		  font-size: 12px;
		  min-width: auto;
		}
		
		.node-types-container {
		  display: flex;
		  flex-direction: column;
		  gap: 10px;
		  margin-top: 8px;
		}
		
		.node-type-item {
		  display: flex;
		  align-items: center;
		  gap: 12px;
		  padding: 12px 16px;
		  border: 2px solid var(--border-color);
		  border-radius: 10px;
		  background: #fff;
		  cursor: pointer;
		  transition: all .3s ease;
		  user-select: none;
		}
		
		.node-type-item:hover {
		  border-color: var(--primary-light);
		  box-shadow: 0 2px 8px rgba(37, 99, 235, 0.1);
		}
		
		.node-type-item.selected {
		  border-color: var(--primary);
		  background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
		  box-shadow: 0 2px 8px rgba(37, 99, 235, 0.2);
		}
		
		.node-type-item.disabled {
		  opacity: 0.4;
		  cursor: not-allowed;
		}
		
		.node-type-item input[type="checkbox"] {
		  width: 18px;
		  height: 18px;
		  accent-color: var(--primary);
		  cursor: pointer;
		  flex-shrink: 0;
		}
		
		.node-type-item.disabled input[type="checkbox"] {
		  cursor: not-allowed;
		}
		
		.node-type-label {
		  font-weight: 600;
		  font-size: 14px;
		  color: var(--text-primary);
		  flex: 1;
		}
		
		.node-type-desc {
		  font-size: 12px;
		  color: var(--text-secondary);
		  margin-top: 2px;
		}
		
		.node-type-badge {
		  font-size: 11px;
		  padding: 2px 8px;
		  border-radius: 6px;
		  background: #fee2e2;
		  color: #991b1b;
		  font-weight: 600;
		}
		
		.node-type-item.selected .node-type-badge {
		  background: #fef3c7;
		  color: #92400e;
		}
		
		.link-arrow {
		  color: var(--primary);
		  text-decoration: none;
		  font-size: 14px;
		  display: inline-flex;
		  align-items: center;
		  justify-content: center;
		  width: 28px;
		  height: 28px;
		  border-radius: 8px;
		  background: var(--bg-gradient-end);
		  transition: all .3s ease;
		  margin-left: 8px;
		}
		
		.link-arrow:hover {
		  background: var(--primary);
		  color: #fff;
		}
		
		.label-with-link {
		  display: flex;
		  align-items: center;
		}
		
		.config-section {
		  display: none;
		}
		
		.config-section.active {
		  display: block;
		}
		
		.collapse-section {
		  margin-bottom: 16px;
		  border: 2px solid var(--border-color);
		  border-radius: 12px;
		  overflow: hidden;
		}
		
		.collapse-header {
		  width: 100%;
		  padding: 16px 20px;
		  background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
		  border: none;
		  cursor: pointer;
		  display: flex;
		  align-items: center;
		  justify-content: space-between;
		  font-size: 16px;
		  font-weight: 600;
		  color: var(--text-primary);
		  transition: all .3s ease;
		}
		
		.collapse-header:hover {
		  background: linear-gradient(135deg, var(--bg-gradient-end) 0%, var(--bg-gradient-start) 100%);
		}
		
		.collapse-header .icon {
		  font-size: 20px;
		  transition: transform .3s ease;
		}
		
		.collapse-header.active .icon {
		  transform: rotate(180deg);
		}
		
		.collapse-content {
		  max-height: 0;
		  overflow: hidden;
		  transition: max-height .3s ease, padding .3s ease;
		  padding: 0 20px;
		}
		
		.collapse-content.active {
		  max-height: 2000px;
		  padding: 20px;
		}
		
		.collapse-content.scroll-area {
		  overflow-y: auto;
		}
		
		.collapse-content.scroll-area.active {
		  max-height: 65vh;
		}
		
		.qr-modal {
		  display: none;
		  position: fixed;
		  top: 0;
		  left: 0;
		  width: 100%;
		  height: 100%;
		  background: rgba(30, 58, 95, 0.6);
		  backdrop-filter: blur(4px);
		  z-index: 1000;
		  align-items: center;
		  justify-content: center;
		  padding: 20px;
		}
		
		.qr-modal.active {
		  display: flex;
		}
		
		.qr-content {
		  background: var(--card-bg);
		  border-radius: 24px;
		  padding: 32px;
		  text-align: center;
		  max-width: 400px;
		  width: 100%;
		  box-shadow: var(--shadow-lg);
		  border: 1px solid var(--border-color);
		  position: relative;
		}
		
		.qr-content::before {
		  content: '';
		  position: absolute;
		  top: 0;
		  left: 0;
		  right: 0;
		  height: 6px;
		  background: linear-gradient(90deg, var(--primary) 0%, var(--primary-light) 100%);
		  border-radius: 24px 24px 0 0;
		}
		
		.qr-title {
		  font-size: 20px;
		  font-weight: 600;
		  color: var(--text-primary);
		  margin-bottom: 8px;
		}
		
		.qr-subtitle {
		  color: var(--text-secondary);
		  font-size: 14px;
		  margin-bottom: 20px;
		}
		
		#qrCanvas {
		  display: flex;
		  justify-content: center;
		  margin: 20px 0;
		  padding: 20px;
		  background: #fff;
		  border-radius: 16px;
		  border: 2px solid var(--border-color);
		}
		
		.qr-close {
		  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
		  color: #fff;
		  border: none;
		  padding: 12px 32px;
		  border-radius: 10px;
		  font-weight: 600;
		  cursor: pointer;
		  transition: all .3s ease;
		}
		
		.qr-close:hover {
		  transform: translateY(-2px);
		  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3);
		}
		
		.toast {
		  position: fixed;
		  bottom: 24px;
		  left: 50%;
		  transform: translateX(-50%) translateY(100px);
		  background: var(--text-primary);
		  color: #fff;
		  padding: 12px 24px;
		  border-radius: 10px;
		  font-size: 14px;
		  opacity: 0;
		  transition: all .3s ease;
		  z-index: 2000;
		}
		
		.toast.show {
		  transform: translateX(-50%) translateY(0);
		  opacity: 1;
		}
		
		.message {
		  margin-top: 12px;
		  padding: 12px 16px;
		  border-radius: 10px;
		  text-align: center;
		  font-size: 14px;
		  font-weight: 500;
		}
		
		.message.success {
		  background: #d1fae5;
		  border: 1px solid #a7f3d0;
		  color: #065f46;
		}
		
		.message.error {
		  background: #fee2e2;
		  border: 1px solid #fecaca;
		  color: #991b1b;
		}
		
		.spinner {
		  display: inline-block;
		  width: 12px;
		  height: 12px;
		  border: 2px solid rgba(255, 255, 255, .35);
		  border-top-color: #fff;
		  border-radius: 50%;
		  animation: spin .8s linear infinite;
		  margin-right: 6px;
		  vertical-align: -2px;
		}
		
		@keyframes spin {
		  to {
		    transform: rotate(360deg);
		  }
		}
		
		@media(max-width: 640px) {
		  .wrap {
		    padding: 14px 12px 28px;
		  }
		
		  .header {
		    margin-bottom: 18px;
		    padding: 12px 0;
		  }
		
		  h1 {
		    font-size: 22px;
		  }
		
		  .subtitle {
		    font-size: 13px;
		  }
		
		  .topbar {
		    position: static;
		    justify-content: center;
		    margin-bottom: 16px;
		  }
		
		  .btn {
		    min-width: 100%;
		    margin-bottom: 6px;
		    padding: 11px 16px;
		    font-size: 14px;
		  }
		
		  .button-group {
		    gap: 8px;
		  }
		
		  .tab-nav {
		    overflow-x: auto;
		    flex-wrap: nowrap;
		    -webkit-overflow-scrolling: touch;
		    scrollbar-width: none;
		  }
		
		  .tab-nav::-webkit-scrollbar {
		    display: none;
		  }
		
		  .tab-btn {
		    white-space: nowrap;
		    flex: none;
		  }
		
		  /* 折叠区：收紧内边距，缩短滚动距离 */
		  .collapse-section {
		    margin-bottom: 12px;
		  }
		
		  .collapse-header {
		    padding: 12px 14px;
		    font-size: 15px;
		  }
		
		  .collapse-content.active {
		    padding: 14px;
		  }
		
		  /* 手机端取消配置区的内部滚动，交给整页滚动，避免嵌套滚动 */
		  .collapse-content.scroll-area.active {
		    max-height: none;
		  }
		
		  .form-group {
		    margin-bottom: 14px;
		  }
		
		  label {
		    margin-bottom: 6px;
		    font-size: 14px;
		  }
		
		  input[type="text"],
		  input[type="number"],
		  input[type="password"] {
		    padding: 10px 12px;
		    border-radius: 8px;
		    font-size: 13px;
		  }
		
		  /* 输入行：允许输入框收缩，按钮不再把输入框挤出容器 */
		  .input-group,
		  .list-item {
		    gap: 6px;
		  }
		
		  .input-group input,
		  .list-item input {
		    min-width: 0;
		  }
		
		  .input-group .btn,
		  .list-item .btn,
		  .chip {
		    padding: 9px 10px;
		    font-size: 12px;
		    margin-bottom: 0;
		  }
		
		  .label-with-link {
		    flex-wrap: wrap;
		    gap: 6px;
		  }
		
		  .label-with-link .btn {
		    min-width: auto;
		    flex: none;
		    margin-bottom: 0;
		    padding: 6px 12px;
		    font-size: 13px;
		  }
		
		  .link-arrow {
		    width: 26px;
		    height: 26px;
		    margin-left: 4px;
		  }
		
		  /* 节点类型：更紧凑 */
		  .node-type-item {
		    padding: 10px 12px;
		    gap: 10px;
		  }
		
		  .node-type-label {
		    font-size: 13.5px;
		    overflow-wrap: anywhere;
		  }
		
		  .node-type-desc {
		    font-size: 11.5px;
		    overflow-wrap: anywhere;
		  }
		
		  .node-type-badge {
		    font-size: 10px;
		    padding: 2px 6px;
		  }
		
		  .url-box {
		    overflow-wrap: anywhere;
		  }
		}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="header">
			<h1>✨ZQ-VTPanel</h1>
			<div class="subtitle">安全、快速、稳定的代理服务</div>
		</div>
		<div class="topbar">
			<a class="gh" href="https://github.com/BAYUEQI/ZQ-VTPanel" target="_blank" rel="nofollow noopener" aria-label="GitHub 项目">
				<svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" fill="currentColor">
					<path
						d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z">
					</path>
				</svg>
			</a>
		</div>
		<div class="main-card">
			<div class="collapse-section">
				<button class="collapse-header active" data-collapse="sub-content">
					<span>📡订阅链接</span>
					<span class="icon">▼</span>
				</button>
				<div class="collapse-content active" id="sub-content">
					<div class="url-box">${subUrl}</div>
					<div class="button-group">
						<button class="btn btn-primary copy" data-text="${subUrl}">📋复制订阅链接</button>
						<button class="btn btn-secondary copy" id="exportNodes">📤导出节点信息</button>
						<button class="btn btn-success" id="showQrBtn">📱显示二维码</button>
					</div>
				</div>
			</div>
			<div class="collapse-section">
				<button class="collapse-header" data-collapse="config-content">
					<span>⚙️配置管理</span>
					<span class="icon">▼</span>
				</button>
				<div class="collapse-content scroll-area" id="config-content">
					<form id="configForm">
						<div class="form-group">
							<label for="uuid">UUID</label>
							<input type="text" id="uuid" name="uuid" required placeholder="请输入UUID">
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label>优选IP(可选)</label>
								<a href="https://ipdb.030101.xyz/bestcfv4/" target="_blank" rel="nofollow noopener" class="link-arrow" title="优选IP地址">↗</a>
								<button type="button" id="toggleBestIpSettings" style="margin-left: 8px; padding: 6px 12px; min-width: auto; flex: none; background: #DAE9FE; color: #2563eb; border-radius: 10px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all .3s ease; display: inline-flex; align-items: center; justify-content: center;">自动优选</button>
							</div>
							<div id="bestIpSettings" style="display: none; margin-bottom: 12px; padding: 12px; background: #f8fafc; border-radius: 8px; border: 1px solid #bfdbfe;">
								<div style="margin-bottom: 8px;">
									<label style="font-size: 13px; font-weight: 600; color: #64748b;">优选IP API地址</label>
									<input type="text" id="bestIpApi" placeholder="${DEFAULT_BEST_IP_API}" style="width: 100%; margin-top: 4px; padding: 8px 12px; border: 2px solid #bfdbfe; border-radius: 6px; font-size: 13px;">
								</div>
								<div style="margin-bottom: 8px;">
									<label style="display: flex; align-items: center; font-size: 13px; font-weight: 600; color: #64748b;">
										<input type="checkbox" id="autoUpdateBestIp" style="margin-right: 8px;">
										自动获取优选IP
									</label>
								</div>
								<div class="button-group" style="margin-bottom: 0;">
									<button type="button" id="fetchBestIp" class="btn btn-success" style="flex: 1; min-width: auto; padding: 10px 16px; font-size: 13px;">🔄获取优选IP</button>
								</div>
							</div>
							<div id="domains" class="list"></div>
							<div class="input-group">
								<input type="text" id="domainNew" placeholder="输入IP">
								<input type="text" id="domainRemarkNew" placeholder="输入备注（可选）">
								<button type="button" id="addDomain" class="btn btn-secondary chip">➕添加</button>
							</div>
						</div>
						<div class="form-group">
							<label>端口(可选)</label>
							<div id="ports" class="list"></div>
							<div class="input-group">
								<input type="number" id="portNew" min="1" max="65535" placeholder="输入端口后点击添加">
								<button type="button" id="addPort" class="btn btn-secondary chip">➕添加</button>
							</div>
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label for="proxyIp">ProxyIP(可选)</label>
								<a href="https://ipdb.030101.xyz/bestproxy/" target="_blank" rel="nofollow noopener" class="link-arrow" title="ProxyIP地址">↗</a>
							</div>
							<div class="input-group">
								<input type="text" id="proxyIp" name="proxyIp" placeholder="格式: host:port 或 host">
							</div>
						</div>
						<div class="form-group">
							<label for="s5">其它代理(可选)</label>
							<div class="input-group">
								<input type="text" id="s5" name="s5" placeholder="格式: [协议://]user:pass@host:port 或 host:port，协议支持 socks5 / http / https / sstp / turn">
							</div>
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label for="subLinkBase">订阅转换服务(可选)</label>
							</div>
							<div class="input-group">
								<input type="text" id="subLinkBase" name="subLinkBase" placeholder="${DEFAULT_SUBLINK_BASE}">
							</div>
						</div>
						<div class="form-group">
							<div class="label-with-link">
								<label for="echEnabled">Encrypted Client Hello(ECH)</label>
								<button type="button" id="toggleEchSettings" style="margin-left: 8px; padding: 6px 12px; min-width: auto; flex: none; background: #DAE9FE; color: #2563eb; border-radius: 10px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all .3s ease; display: inline-flex; align-items: center; justify-content: center;">高级</button>
							</div>
							<label style="display: flex; align-items: center; font-size: 14px; font-weight: 600; color: #64748b; margin-top: 8px;">
								<input type="checkbox" id="echEnabled" name="echEnabled" style="margin-right: 8px;">
								启用 ECH 
							</label>
							<div id="echSettings" style="display: none; margin-top: 12px; padding: 12px; background: #f8fafc; border-radius: 8px; border: 1px solid #bfdbfe;">
								<div style="margin-bottom: 8px;">
									<label style="font-size: 13px; font-weight: 600; color: #64748b;">ECH 解析域名 (SNI)</label>
									<input type="text" id="echSni" placeholder="${DEFAULT_ECH_SNI}" style="width: 100%; margin-top: 4px; padding: 8px 12px; border: 2px solid #bfdbfe; border-radius: 6px; font-size: 13px;">
								</div>
								<div style="margin-bottom: 8px;">
									<label style="font-size: 13px; font-weight: 600; color: #64748b;">ECH DNS 服务 (DoH)</label>
									<input type="text" id="echDns" placeholder="${DEFAULT_ECH_DNS}" style="width: 100%; margin-top: 4px; padding: 8px 12px; border: 2px solid #bfdbfe; border-radius: 6px; font-size: 13px;">
								</div>
							</div>
						</div>
						<div class="form-group">
							<label>节点类型选择 <span style="color: #dc2626; font-size: 12px;">(至少选择一个)</span></label>
							<div class="node-types-container" id="nodeTypesContainer">
								<div class="node-type-item" data-type="direct" data-require="">
									<input type="checkbox" class="node-type-checkbox" value="direct" checked>
									<div style="flex: 1;">
										<div class="node-type-label">🟢 直连</div>
										<div class="node-type-desc">直接连接非 Cloudflare CDN 站点</div>
									</div>
								</div>
								<div class="node-type-item" data-type="s5" data-require="s5">
									<input type="checkbox" class="node-type-checkbox" value="s5" disabled>
									<div style="flex: 1;">
										<div class="node-type-label">🔵 其它代理</div>
										<div class="node-type-desc">仅使用其它代理连接目标，不做直连回退</div>
									</div>
									<span class="node-type-badge" id="badge-s5">需填写其它代理</span>
								</div>
								<div class="node-type-item" data-type="direct_s5" data-require="s5">
									<input type="checkbox" class="node-type-checkbox" value="direct_s5" disabled>
									<div style="flex: 1;">
										<div class="node-type-label">🟡 直连 + 其它代理</div>
										<div class="node-type-desc">优先直连，失败后回退到其它代理</div>
									</div>
									<span class="node-type-badge" id="badge-direct_s5">需填写其它代理</span>
								</div>
								<div class="node-type-item" data-type="direct_proxy" data-require="proxyIp">
									<input type="checkbox" class="node-type-checkbox" value="direct_proxy" disabled>
									<div style="flex: 1;">
										<div class="node-type-label">🟣 直连 + ProxyIP</div>
										<div class="node-type-desc">优先直连，失败后回退到ProxyIP中转</div>
									</div>
									<span class="node-type-badge" id="badge-direct_proxy">需填写ProxyIP</span>
								</div>
								<div class="node-type-item" data-type="direct_s5_proxy" data-require="s5_proxy">
									<input type="checkbox" class="node-type-checkbox" value="direct_s5_proxy" disabled>
									<div style="flex: 1;">
										<div class="node-type-label">🟤 直连 + 其它代理 + ProxyIP</div>
										<div class="node-type-desc">直连→其它代理→ProxyIP，多重回退</div>
									</div>
									<span class="node-type-badge" id="badge-direct_s5_proxy">需填写其它代理+ProxyIP</span>
								</div>
							</div>
						</div>
						<div class="form-group">
							<label>协议类型选择 <span style="color: #dc2626; font-size: 12px;">(至少选择一个)</span></label>
							<div class="node-types-container" id="protocolsContainer">
								<div class="node-type-item" data-protocol="vless">
									<input type="checkbox" class="protocol-checkbox" value="vless" checked>
									<div style="flex: 1;">
										<div class="node-type-label">🟦 VLESS</div>
										<div class="node-type-desc">Xray 原生协议，性能优秀，推荐使用</div>
									</div>
								</div>
								<div class="node-type-item" data-protocol="trojan">
									<input type="checkbox" class="protocol-checkbox" value="trojan" checked>
									<div style="flex: 1;">
										<div class="node-type-label">🟧 Trojan</div>
										<div class="node-type-desc">简洁高效，伪装性强，兼容性好</div>
									</div>
								</div>
							</div>
						</div>
						<div class="form-group">
							<label for="fallbackTimeout">回退检测时间(可选)</label>
							<div class="input-group">
								<input type="number" id="fallbackTimeout" name="fallbackTimeout" min="1" max="5000" placeholder="默认100毫秒">
							</div>
						</div>
						<div class="button-group">
							<button type="submit" class="btn btn-primary">💾保存配置</button>
							<button type="button" class="btn btn-secondary" id="reloadBtn">🔄重新加载</button>
						</div>
						<div id="message" class="message" style="display:none"></div>
					</form>
				</div>
			</div>
		</div>
		<div class="qr-modal" id="qrModal">
			<div class="qr-content">
				<div class="qr-title">📱扫码订阅</div>
				<div class="qr-subtitle">使用客户端扫描二维码快速添加</div>
				<div id="qrCanvas"></div>
				<button class="qr-close" id="closeQrBtn">关闭</button>
			</div>
		</div>
		<div class="toast" id="toast"></div>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
		<script>
			(function() {
			    // 登录成功后立刻把地址栏里的 ?pwd=... 清掉
			    if (location.search) history.replaceState(null, '', location.pathname);

			    const toastEl = document.getElementById('toast');
			
			    function showToast(msg) {
			        toastEl.textContent = msg;
			        toastEl.classList.add('show');
			        setTimeout(() => toastEl.classList.remove('show'), 2000);
			    }
			
			    function showMessage(text, type) {
			        const el = document.getElementById('message');
			        el.textContent = text;
			        el.className = 'message ' + type;
			        el.style.display = 'block';
			        setTimeout(() => {
			            el.style.display = 'none';
			        }, 3000);
			    }
			
			    function fallbackCopy(text) {
			        const ta = document.createElement('textarea');
			        ta.value = text;
			        ta.setAttribute('readonly', '');
			        ta.style.position = 'absolute';
			        ta.style.left = '-9999px';
			        document.body.appendChild(ta);
			        ta.select();
			        let ok = false;
			        try {
			            ok = document.execCommand('copy');
			        } catch (e) {}
			        document.body.removeChild(ta);
			        return ok;
			    }
			
			    async function doCopy(btn) {
			        const t = btn.getAttribute('data-text');
			        if (!t) return;
			        let ok = false;
			        
			        if (navigator.clipboard && navigator.clipboard.writeText) {
			            try {
			                await navigator.clipboard.writeText(t);
			                ok = true;
			            } catch (e) {
			                ok = false;
			            }
			        }
			        
			        if (!ok) {
			            ok = fallbackCopy(t);
			        }
			        
			        showToast(ok ? '✅ 已复制到剪贴板' : '❌ 复制失败');
			    }
			
			    document.querySelectorAll('button.copy').forEach(b => 
			        b.addEventListener('click', e => {
			            doCopy(e.currentTarget);
			        })
			    );
			
			    const exportBtn = document.getElementById('exportNodes');
			    if (exportBtn) {
			        exportBtn.addEventListener('click', async () => {
			            const allNodes = ${allNodesJson};
			            const nodeText = allNodes.join('\\n') + '\\n';
			            const nodeTextBase64 = btoa(unescape(encodeURIComponent(nodeText)));
			            let ok = false;
			            
			            if (navigator.clipboard && navigator.clipboard.writeText) {
			                try {
			                    await navigator.clipboard.writeText(nodeTextBase64);
			                    ok = true;
			                } catch (e) {
			                    ok = false;
			                }
			            }
			            
			            if (!ok) {
			                ok = fallbackCopy(nodeTextBase64);
			            }
			            
			            showToast(ok ? '✅ 已导出到剪贴板' : '❌ 导出失败');
			        });
			    }
			
			    const showQrBtn = document.getElementById('showQrBtn');
			    const qrModal = document.getElementById('qrModal');
			    const closeQrBtn = document.getElementById('closeQrBtn');
			    const qrCanvas = document.getElementById('qrCanvas');
			    let qrCode = null;
			
			    showQrBtn.addEventListener('click', () => {
			        qrModal.classList.add('active');
			        if (!qrCode) {
			            qrCode = new QRCode(qrCanvas, {
			                text: '${subUrl}',
			                width: 220,
			                height: 220,
			                colorDark: '#2563eb',
			                colorLight: '#ffffff',
			                correctLevel: QRCode.CorrectLevel.M
			            });
			        }
			    });
			
			    closeQrBtn.addEventListener('click', () => {
			        qrModal.classList.remove('active');
			    });
			
			    qrModal.addEventListener('click', (e) => {
			        if (e.target === qrModal) qrModal.classList.remove('active');
			    });
			
			    const tabBtns = document.querySelectorAll('.tab-btn');
			    const configSections = document.querySelectorAll('.config-section');
			
			    tabBtns.forEach(btn => {
			        btn.addEventListener('click', () => {
			            const tab = btn.dataset.tab;
			            tabBtns.forEach(b => b.classList.remove('active'));
			            configSections.forEach(s => s.classList.remove('active'));
			            btn.classList.add('active');
			            document.getElementById(tab + '-section').classList.add('active');
			        });
			    });
			
			    function renderList(container, values, placeholder, isPort) {
			        container.innerHTML = '';
			        values.forEach((val, idx) => {
			            const row = document.createElement('div');
			            row.className = 'list-item';
			            
			            if (isPort) {
			                const input = document.createElement('input');
			                input.type = 'number';
			                input.min = '1';
			                input.max = '65535';
			                input.value = String(val);
			                input.placeholder = placeholder;
			                
			                const del = document.createElement('button');
			                del.type = 'button';
			                del.className = 'btn btn-danger chip';
			                del.textContent = '🗑️ 删除';
			                del.addEventListener('click', () => {
			                    values.splice(idx, 1);
			                    renderList(container, values, placeholder, isPort);
			                });
			                
			                row.appendChild(input);
			                row.appendChild(del);
			                container.appendChild(row);
			                
			                input.addEventListener('input', () => {
			                    values[idx] = Number(Math.max(1, Math.min(65535, parseInt(input.value || '0', 10))));
			                });
			            } else {
			                const ipInput = document.createElement('input');
			                ipInput.type = 'text';
			                ipInput.value = val.ip || '';
			                ipInput.placeholder = 'IP地址';
			                ipInput.style.flex = '1';
			                
			                const remarkInput = document.createElement('input');
			                remarkInput.type = 'text';
			                remarkInput.value = val.remark || '';
			                remarkInput.placeholder = '备注（可选）';
			                remarkInput.style.flex = '1';
			                
			                const del = document.createElement('button');
			                del.type = 'button';
			                del.className = 'btn btn-danger chip';
			                del.textContent = '🗑️ 删除';
			                del.addEventListener('click', () => {
			                    values.splice(idx, 1);
			                    renderList(container, values, placeholder, isPort);
			                });
			                
			                row.appendChild(ipInput);
			                row.appendChild(remarkInput);
			                row.appendChild(del);
			                container.appendChild(row);
			                
			                ipInput.addEventListener('input', () => {
			                    values[idx].ip = ipInput.value.trim();
			                });
			                
			                remarkInput.addEventListener('input', () => {
			                    values[idx].remark = remarkInput.value.trim();
			                });
			            }
			        });
			    }
			
			    const state = { domains: [], ports: [] };
			
			    function updateNodeTypeAvailability() {
			        const s5Val = (document.getElementById('s5')?.value || '').trim();
			        const proxyIpVal = (document.getElementById('proxyIp')?.value || '').trim();
			        
			        document.querySelectorAll('.node-type-item').forEach(item => {
			            const require = item.getAttribute('data-require') || '';
			            const checkbox = item.querySelector('.node-type-checkbox');
			            if (!checkbox) return; // 跳过协议类型卡片
			            let canUse = true;
			            
			            if (require === 's5' && !s5Val) canUse = false;
			            if (require === 'proxyIp' && !proxyIpVal) canUse = false;
			            if (require === 's5_proxy' && (!s5Val || !proxyIpVal)) canUse = false;
			            
			            if (canUse) {
			                item.classList.remove('disabled');
			                checkbox.disabled = false;
			            } else {
			                item.classList.add('disabled');
			                checkbox.disabled = true;
			                checkbox.checked = false;
			                item.classList.remove('selected');
			            }
			        });
			    }
			    
			    function updateNodeTypeSelectedStyle() {
			        document.querySelectorAll('.node-type-item').forEach(item => {
			            const checkbox = item.querySelector('.node-type-checkbox');
			            if (!checkbox) return; // 跳过协议类型卡片
			            if (checkbox.checked) {
			                item.classList.add('selected');
			            } else {
			                item.classList.remove('selected');
			            }
			        });
			    }
			
			    async function loadConfig() {
			        try {
			            const response = await fetch('/api/config');
			            if (!response.ok) throw 0;
			            
			            const cfg = await response.json();
			            document.getElementById('uuid').value = cfg.uuid || '';
                            document.getElementById('s5').value = cfg.s5 || '';
                            document.getElementById('proxyIp').value = cfg.proxyIp || '';
                            document.getElementById('fallbackTimeout').value = cfg.fallbackTimeout || 100;
                            document.getElementById('bestIpApi').value = cfg.bestIpApi || 'https://ipdb.api.030101.xyz/?type=bestcf';
                            document.getElementById('subLinkBase').value = cfg.subLinkBase || '${DEFAULT_SUBLINK_BASE}';
                            document.getElementById('echEnabled').checked = !!cfg.ech;
                            const echCfg = cfg.echConfig && typeof cfg.echConfig === 'object' ? cfg.echConfig : {};
                            document.getElementById('echSni').value = echCfg.sni || '';
                            document.getElementById('echDns').value = echCfg.dns || '';
			            document.getElementById('autoUpdateBestIp').checked = !!cfg.autoUpdateBestIp;
			            
			            const savedNodeTypes = Array.isArray(cfg.nodeTypes) && cfg.nodeTypes.length > 0
			                ? cfg.nodeTypes
			                : ["direct"];
			            updateNodeTypeAvailability();
			            document.querySelectorAll('.node-type-checkbox').forEach(cb => {
			                const item = cb.closest('.node-type-item');
			                if (!item.classList.contains('disabled')) {
			                    cb.checked = savedNodeTypes.includes(cb.value);
			                    if (cb.checked) {
			                        item.classList.add('selected');
			                    }
			                } else {
			                    cb.checked = false;
			                    item.classList.remove('selected');
			                }
			            });
			            
			            const savedProtocols = Array.isArray(cfg.protocols) && cfg.protocols.length > 0
			                ? cfg.protocols
			                : ["vless", "trojan"];
			            document.querySelectorAll('.protocol-checkbox').forEach(cb => {
			                const item = cb.closest('.node-type-item');
			                cb.checked = savedProtocols.includes(cb.value);
			                if (cb.checked) {
			                    item.classList.add('selected');
			                } else {
			                    item.classList.remove('selected');
			                }
			            });
			            
			            if (Array.isArray(cfg.domains)) {
			                state.domains = cfg.domains.map(item => {
			                    if (typeof item === 'string') {
			                        return { ip: item, remark: '' };
			                    }
			                    return item;
			                });
			            } else {
			                state.domains = [];
			            }
			            
			            if ((cfg.domain || '').trim() && !state.domains.some(x => x.ip === cfg.domain.trim())) {
			                state.domains.unshift({ ip: cfg.domain.trim(), remark: '' });
			            }
			            
			            state.ports = (Array.isArray(cfg.ports) ? cfg.ports : [])
			                .map(x => parseInt(x, 10))
			                .filter(n => n > 0 && n <= 65535);
			            
			            if (parseInt(cfg.port, 10)) state.ports.unshift(parseInt(cfg.port, 10));
			            
			            state.ports = [...new Set(state.ports)];
			            
			            renderList(document.getElementById('domains'), state.domains, '', false);
			            renderList(document.getElementById('ports'), state.ports, '如: 443', true);
			            
			            showMessage('✅ 配置加载成功', 'success');
			        } catch (e) {
			            showMessage('❌ 配置加载失败', 'error');
			        }
			    }
			
			    async function saveConfigForm() {
			        const uuid = document.getElementById('uuid').value.trim();
                        const s5 = document.getElementById('s5').value.trim();
                        const proxyIp = document.getElementById('proxyIp').value.trim();
                        const fallbackTimeout = parseInt(document.getElementById('fallbackTimeout').value, 10) || 100;
                        const bestIpApi = document.getElementById('bestIpApi').value.trim() || 'https://ipdb.api.030101.xyz/?type=bestcf';
                        const subLinkBase = document.getElementById('subLinkBase').value.trim();
                        // 注意：面板 HTML 是模板字符串，这里刻意不用正则，避免反斜杠被模板转义吃掉
                        if (subLinkBase && !(subLinkBase.startsWith('http://') || subLinkBase.startsWith('https://'))) {
                            showMessage('❌ 订阅转换服务地址需以 http:// 或 https:// 开头', 'error');
                            return;
                        }
                        if (subLinkBase && (subLinkBase.indexOf('?') !== -1 || subLinkBase.indexOf('#') !== -1)) {
                            showMessage('❌ 订阅转换服务地址只填服务根地址，不要带 ? 参数', 'error');
                            return;
                        }
                        const autoUpdateBestIp = document.getElementById('autoUpdateBestIp').checked;
                        const ech = document.getElementById('echEnabled').checked;
                        const echSni = document.getElementById('echSni').value.trim();
                        const echDns = document.getElementById('echDns').value.trim();
                        const echConfig = { sni: echSni, dns: echDns };
			        
			        const nodeTypes = [];
			        document.querySelectorAll('.node-type-checkbox').forEach(cb => {
			            if (cb.checked && !cb.closest('.node-type-item').classList.contains('disabled')) {
			                nodeTypes.push(cb.value);
			            }
			        });
			        
			        if (nodeTypes.length === 0) {
			            showMessage('❌ 请至少选择一个节点类型', 'error');
			            return;
			        }
			        
			        const protocols = [];
			        document.querySelectorAll('.protocol-checkbox').forEach(cb => {
			            if (cb.checked) {
			                protocols.push(cb.value);
			            }
			        });
			        
			        if (protocols.length === 0) {
			            showMessage('❌ 请至少选择一个协议类型', 'error');
			            return;
			        }
			        
			        const domainItems = Array.from(document.querySelectorAll('#domains .list-item'));
			        const domains = [];
			        domainItems.forEach(row => {
			            const inputs = row.querySelectorAll('input');
			            if (inputs.length >= 2) {
			                const ip = inputs[0].value.trim();
			                const remark = inputs[1].value.trim();
			                if (ip) domains.push({ ip, remark });
			            }
			        });
			        
			        const ports = Array.from(document.querySelectorAll('#ports .list-item input'))
			            .map(i => parseInt(i.value, 10))
			            .filter(n => n > 0 && n <= 65535);
			        
			        const body = { uuid, s5, proxyIp, domains, ports, fallbackTimeout, subLinkBase, bestIpApi, autoUpdateBestIp, nodeTypes, protocols, ech, echConfig };
			        
			        const response = await fetch('/api/config', {
			            method: 'POST',
			            headers: { 'content-type': 'application/json' },
			            body: JSON.stringify(body)
			        });
			        
			        const result = await response.json();
			        
			        if (response.ok) {
			            showMessage('✅ ' + (result.message || '配置保存成功'), 'success');
			            setTimeout(() => {
			                window.location.href = '/';
			            }, 800);
			        } else {
			            showMessage('❌ ' + (result.error || '配置保存失败'), 'error');
			        }
			    }
			
			    document.addEventListener('DOMContentLoaded', () => {
			        const collapseHeaders = document.querySelectorAll('.collapse-header');
			        collapseHeaders.forEach(header => {
			            header.addEventListener('click', () => {
			                const targetId = header.getAttribute('data-collapse');
			                const content = document.getElementById(targetId);
			                const isActive = header.classList.contains('active');
			                
			                if (isActive) {
			                    header.classList.remove('active');
			                    content.classList.remove('active');
			                } else {
			                    header.classList.add('active');
			                    content.classList.add('active');
			                }
			            });
			        });
			        
			        const addDomain = document.getElementById('addDomain');
			        const addPort = document.getElementById('addPort');
			        const domainNew = document.getElementById('domainNew');
			        const domainRemarkNew = document.getElementById('domainRemarkNew');
			        const portNew = document.getElementById('portNew');
			        const reloadBtn = document.getElementById('reloadBtn');
			        const toggleBestIpSettings = document.getElementById('toggleBestIpSettings');
			        const fetchBestIp = document.getElementById('fetchBestIp');
			        
			        addDomain && addDomain.addEventListener('click', () => {
			            const v = (domainNew.value || '').trim();
			            const r = (domainRemarkNew.value || '').trim();
			            if (!v) return;
			            state.domains.push({ ip: v, remark: r });
			            renderList(document.getElementById('domains'), state.domains, '', false);
			            domainNew.value = '';
			            domainRemarkNew.value = '';
			        });
			        
			        addPort && addPort.addEventListener('click', () => {
			            const n = parseInt(portNew.value || '0', 10);
			            if (!n || n < 1 || n > 65535) return;
			            state.ports.push(n);
			            renderList(document.getElementById('ports'), state.ports, '如: 443', true);
			            portNew.value = '';
			        });
			        
			        reloadBtn && reloadBtn.addEventListener('click', () => {
			            loadConfig();
			        });
			        
			        toggleBestIpSettings && toggleBestIpSettings.addEventListener('click', () => {
			            const settings = document.getElementById('bestIpSettings');
				            if (settings.style.display === 'none') {
				                settings.style.display = 'block';
				            } else {
				                settings.style.display = 'none';
				            }
				        });

				        const toggleEchSettings = document.getElementById('toggleEchSettings');
				        toggleEchSettings && toggleEchSettings.addEventListener('click', () => {
				            const echSettings = document.getElementById('echSettings');
				            if (echSettings.style.display === 'none') {
				                echSettings.style.display = 'block';
				            } else {
				                echSettings.style.display = 'none';
				            }
				        });
			        
			        fetchBestIp && fetchBestIp.addEventListener('click', async () => {
			            const uuid = document.getElementById('uuid').value.trim() || '${userUUID}';
			            const bestIpApiInput = document.getElementById('bestIpApi');
			            const apiUrl = bestIpApiInput.value.trim() || 'https://ipdb.api.030101.xyz/?type=bestcf';
			
			            const originalText = fetchBestIp.textContent;
			            fetchBestIp.textContent = '⏳ 获取中...';
			            fetchBestIp.disabled = true;
			
			            try {
			                const response = await fetch('/api/fetch-best-ip', {
			                    method: 'POST',
			                    headers: { 'Content-Type': 'application/json' },
			                    body: JSON.stringify({ uuid, apiUrl })
			                });
			                const result = await response.json();
			
			                if (result.success && result.ips && result.ips.length > 0) {
			                    const existingIps = new Set(state.domains.map(d => d.ip));
			                    let addedCount = 0;
			                    result.ips.forEach(ip => {
			                        if (!existingIps.has(ip)) {
			                            state.domains.push({ ip, remark: '优选IP' });
			                            addedCount++;
			                        }
			                    });
			                    renderList(document.getElementById('domains'), state.domains, '', false);
			                    showMessage('✅ 成功添加 ' + addedCount + ' 个优选IP', 'success');
			                } else {
			                    showMessage('❌ 未获取到优选IP', 'error');
			                }
			            } catch (error) {
			                showMessage('❌ 获取优选IP失败: ' + error.message, 'error');
			            } finally {
			                fetchBestIp.textContent = originalText;
			                fetchBestIp.disabled = false;
			            }
			        });
			        
			        // 监听其它代理和 ProxyIP 输入变化，动态更新节点类型可用性
			        const s5Input = document.getElementById('s5');
			        const proxyIpInput = document.getElementById('proxyIp');
			        s5Input && s5Input.addEventListener('input', () => {
			            updateNodeTypeAvailability();
			            // 如果因禁用被取消勾选，需要更新样式
			            updateNodeTypeSelectedStyle();
			        });
			        proxyIpInput && proxyIpInput.addEventListener('input', () => {
			            updateNodeTypeAvailability();
			            updateNodeTypeSelectedStyle();
			        });
			        
			        document.querySelectorAll('.node-type-item').forEach(item => {
			            item.addEventListener('click', (e) => {
			                const checkbox = item.querySelector('input[type="checkbox"]');
			                if (item.classList.contains('disabled') || !checkbox) {
			                    e.preventDefault();
			                    return;
			                }
			                if (e.target !== checkbox) {
			                    checkbox.checked = !checkbox.checked;
			                }
			                if (checkbox.checked) {
			                    item.classList.add('selected');
			                } else {
			                    item.classList.remove('selected');
			                }
			            });
			        });
			    });
			
			    document.getElementById('configForm').addEventListener('submit', function(e) {
			        e.preventDefault();
			        saveConfigForm();
			    });
			
			    loadConfig();
			})();
		</script>
</body>
</html>`;
            const panelHeaders = { "content-type": "text/html; charset=utf-8" };
            if (cookieSetHeader) panelHeaders["set-cookie"] = cookieSetHeader;
            return new Response(html, { headers: panelHeaders });
        }
        return new Response("Not Found", { status: 404 });
    },
    async scheduled(event, env, ctx) {
        try {
            const cfg = await getUserConfig(env);
            if (!cfg.autoUpdateBestIp || !cfg.bestIpApi) {
                console.log("Auto update best IP is disabled or no API configured");
                return;
            }

            console.log("Starting scheduled best IP update");
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            try {
                const response = await fetch(cfg.bestIpApi, {
                    method: 'get',
                    headers: {
                        "Accept": "text/html,application/xhtml+xml,application/xml;",
                        "User-Agent": "cmliu/CF-Workers-DD2D",
                    },
                    signal: controller.signal,
                });

                if (!response.ok) {
                    throw new Error(`API request failed: ${response.status}`);
                }

                const text = await response.text();
                const newIps = text.replace(/[ \t\r\n]+/g, ',').replace(/,+/g, ',').replace(/^,|,$/g, '').split(',').filter(Boolean);
                const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))$/;

                const ips = newIps.filter(ip => ipv4Regex.test(ip) || ipv6Regex.test(ip));

                if (ips.length > 0) {
                    let domains = Array.isArray(cfg.domains)
                        ? cfg.domains.map((item) => {
                            if (typeof item === 'string') {
                                return { ip: item, remark: '' };
                            }
                            return item;
                        }).filter(x => x && x.ip)
                        : [];

                    if (cfg.domain && !domains.some(x => x.ip === cfg.domain)) {
                        domains.unshift({ ip: cfg.domain, remark: '' });
                    }

                    const existingIps = new Set(domains.map(d => d.ip));
                    const nonPreferredIps = domains.filter(d => d.remark !== '优选IP');
                    const preferredIps = ips
                        .filter(ip => !existingIps.has(ip))
                        .map(ip => ({ ip, remark: '优选IP' }));

                    domains = [...nonPreferredIps, ...preferredIps];

                    if (domains.length > 20) {
                        domains = domains.slice(0, 20);
                    }

                    const normalized = {
                        uuid: cfg.uuid,
                        domain: domains[0]?.ip || '',
                        port: cfg.port,
                        s5: cfg.s5 || '',
                        proxyIp: cfg.proxyIp || '',
                        domains: domains,
                        ports: cfg.ports || [443],
                        fallbackTimeout: cfg.fallbackTimeout || 100,
                        // 注意：这里会整份回写配置，前端新增的字段必须一并带上，否则会被定时任务抹掉
                        subLinkBase: normalizeSubLinkBase(cfg.subLinkBase) || DEFAULT_SUBLINK_BASE,
                        bestIpApi: cfg.bestIpApi,
                        autoUpdateBestIp: cfg.autoUpdateBestIp,
                        nodeTypes: cfg.nodeTypes && cfg.nodeTypes.length > 0 ? cfg.nodeTypes : ["direct"],
                        protocols: cfg.protocols && cfg.protocols.length > 0 ? cfg.protocols : ["vless", "trojan"],
                        ech: !!cfg.ech,
                        echConfig: {
                            sni: cfg.echConfig?.sni || DEFAULT_ECH_SNI,
                            dns: cfg.echConfig?.dns || DEFAULT_ECH_DNS,
                        },
                    };

                    if (env.VTPanel) {
                        await env.VTPanel.put("user_config", JSON.stringify(normalized));
                    }

                    console.log(`Successfully updated ${preferredIps.length} best IPs`);
                } else {
                    console.log("No valid IPs received from API");
                }
            } finally {
                clearTimeout(timeout);
            }
        } catch (error) {
            console.error("Error in scheduled best IP update:", error);
        }
    },
};
