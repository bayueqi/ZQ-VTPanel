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

const json=(c,s=200)=>new Response(JSON.stringify(c),{status:s,headers:{"content-type":"application/json; charset=utf-8"}});
const b64e=(s)=>{const b=new TextEncoder().encode(s);let bin="";for(let i=0;i<b.length;i+=0x8000)bin+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));return btoa(bin);};
// gRPC 服务名里放参数的写法用它：URL 安全、无填充
const b64urlEnc=(s)=>b64e(String(s)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const b64urlDec=(s)=>{
    try{
        const t=String(s).replace(/-/g,"+").replace(/_/g,"/");
        return atob(t+"=".repeat((4-t.length%4)%4));
    }catch{return "";}
};
const randStr=()=>Math.random().toString(36).slice(2,8);
const paths=["/static/js","/assets/img","/api/2024","/cdn/file","/upload/data","/media/v2","/lib/ext","/res/now","/stat/click","/track/log","/api/v1/data","/css/main","/js/app","/fonts/google","/images/hero","/videos/intro","/api/v2/user","/assets/css","/static/media","/build/js","/dist/css","/public/img","/content/data","/files/doc","/download/pkg","/api/v3/item","/resource/img"];
const paramsMap={t:["m","type","mode"],d:["dir","direct","d"],s:["socks","proxy","s"],p:["ip","proxyip","p"],v:["r","rand","v","id"]};
const getPath=()=>paths[Math.floor(Math.random()*paths.length)];
const getParam=(key)=>paramsMap[key][Math.floor(Math.random()*paramsMap[key].length)];

// xhttp 混淆：标识头/键由 UUID 派生。客户端把查询串塞进这个请求头，服务端据此认出 xhttp，
// 顺带挡掉直接照抄路径的扫描器（真客户端的 padding 串长度固定在百位级）
const xhttpTag=(uuid)=>{
    const s=String(uuid||DEFAULT_UUID);
    return [s.slice(1,7),"_"+s.slice(25,31)];
};
const xhttpExtra=(uuid)=>{
    const [header,key]=xhttpTag(uuid);
    return {xPaddingObfsMode:true,xPaddingMethod:"tokenish",xPaddingPlacement:"queryInHeader",xPaddingHeader:header,xPaddingKey:key};
};
const randPad=(n)=>{
    const chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let s="";
    for(let i=0;i<n;i++) s+=chars[Math.floor(Math.random()*chars.length)];
    return s;
};
// 头里的值是一整个 URL，padding 串在它的查询串里；取不到再退回请求自己的查询串
const xhttpPadding=(req,header,key)=>{
    const raw=req.headers.get(header);
    if(raw){
        try{
            const v=new URL(raw,"https://x.invalid").searchParams.get(key);
            if(v) return v;
        }catch{}
        return raw;
    }
    return new URL(req.url).searchParams.get(key)||"";
};

// ----------- 共享常量和工具 -----------
const DEFAULT_UUID = "ef9d104e-ca0e-4202-ba4b-a0afb969c747";
const TRANSPORTS = ["ws", "xhttp", "grpc"];
// 节点名里的传输标记：W = WebSocket，X = XHTTP，G = gRPC
const TRANSPORT_BADGE = { ws: "W", xhttp: "X", grpc: "G" };
// 客户端各端点支持的传输层：sing-box 没有 xhttp，surge / loon / quanx 只认 ws
const TRANSPORT_UNSUPPORTED = {
    singbox: ["xhttp"],
    surge: ["xhttp", "grpc"],
    loon: ["xhttp", "grpc"],
    quanx: ["xhttp", "grpc"],
};
// 新版存 transports 数组，旧配置只有单个 transport，一并兼容
const normalizeTransports = (m) => {
    const src = Array.isArray(m && m.transports) ? m.transports
        : (m && typeof m.transport === "string" ? [m.transport] : []);
    const out = TRANSPORTS.filter((t) => src.includes(t));
    return out.length ? out : ["ws"];
};
const DEFAULT_BEST_IP_API = "https://ipdb.api.030101.xyz/?type=bestcf";
const DEFAULT_PROXY_API = "https://texturl.520jk.cc.cd/csp";
const SUPPORTED_PROXY_PROTOCOLS = ["socks5", "http", "https", "sstp"];
const DEFAULT_ECH_SNI = "cloudflare-ech.com";
const DEFAULT_ECH_DNS = "https://sm2.doh.pub/dns-query";
// 订阅转换服务（subconverter 接口，ZQ-SubApi 就是这一层）。可用环境变量 SUBCONVERTER_BASE 覆盖。
const DEFAULT_SUBCONVERTER_BASE = "https://subapi.vpnjk.cc.cd";
// 客户端格式 -> subconverter 的 target 参数；未列出的（mixed / quanx / loon 等）直接返回 base64 节点列表
const SUBCONVERTER_TARGETS = { clash: "clash", singbox: "singbox", surge: "surge" };
// 订阅转换服务地址归一化：只接受 http(s):// 的服务根地址，去掉尾部斜杠。
// 带 ? 或 # 说明用户贴的是完整订阅/转换链接而不是服务地址，一律判为非法并返回 ""（由调用方回退默认值）
function normalizeServiceBase(v) {
    if (typeof v !== "string") return "";
    const s = v.trim().replace(/\/+$/, "");
    if (/[?#]/.test(s)) return "";
    return /^https?:\/\/[^\s/]+/i.test(s) ? s : "";
}
// 订阅转换配置文件：subconverter 的 config= 参数，仅对 clash 生效
const SUB_CONFIG_BASE = "https://raw.githubusercontent.com/bayueqi/ZQ-JKPanel/main/";
// 面板地址：docs/ 静态页的根地址，或 jkpanel.js 部署后的域名，可用环境变量 PANEL_URL 覆盖
const DEFAULT_PANEL_URL = "https://jkpanel.vpnjk.cc.cd";
const SUB_CONFIG_PRESETS = [
    ["", "不使用"],
    ["ZQ-AllInOne.ini", "全能版"],
];
// 配置文件地址归一化：空串 = 不启用；预设名补全成完整 raw 地址；也接受用户自填的 http(s) 地址
function normalizeSubConfig(v) {
    if (typeof v !== "string") return "";
    const s = v.trim();
    if (!s) return "";
    if (SUB_CONFIG_PRESETS.some(([f]) => f && f === s)) return SUB_CONFIG_BASE + s;
    if (/[?#]/.test(s)) return "";
    return /^https?:\/\/[^\s/]+/i.test(s) ? s : "";
}
// 配置落盘：把一份配置归一化成存储用的完整结构。
// 面板保存和定时任务回写都走这里，字段只有一处定义，不会出现某条路径漏写。
function configForStore(cfg, overrides = {}) {
    const m = { ...cfg, ...overrides };
    return {
        uuid: m.uuid,
        password: typeof m.password === "string" ? m.password.trim() : "",
        domains: normalizeDomains(m.domains),
        proxyIps: Array.isArray(m.proxyIps) ? m.proxyIps : [],
        entries: Array.isArray(m.entries) ? m.entries : [],
        proxies: Array.isArray(m.proxies) ? m.proxies : [],
        globalProxy: !!m.globalProxy,
        subConvertBase: normalizeServiceBase(m.subConvertBase) || DEFAULT_SUBCONVERTER_BASE,
        subConfig: normalizeSubConfig(m.subConfig),
        bestIpApi: m.bestIpApi || DEFAULT_BEST_IP_API,
        autoUpdateBestIp: !!m.autoUpdateBestIp,
        proxyApi: typeof m.proxyApi === "string" ? m.proxyApi.trim() : "",
        autoUpdateProxies: !!m.autoUpdateProxies,
        proxyProtocols: (m.proxyProtocols && m.proxyProtocols.length) ? m.proxyProtocols : SUPPORTED_PROXY_PROTOCOLS,
        protocols: (m.protocols && m.protocols.length) ? m.protocols : ["vless", "trojan"],
        transports: normalizeTransports(m),
        grpcMode: m.grpcMode === "multi" ? "multi" : "gun",
        grpcUA: typeof m.grpcUA === "string" ? m.grpcUA.trim().slice(0, 256) : "",
        ech: !!m.ech,
        echConfig: {
            sni: (typeof m.echConfig?.sni === "string" ? m.echConfig.sni.trim() : "") || DEFAULT_ECH_SNI,
            dns: (typeof m.echConfig?.dns === "string" ? m.echConfig.dns.trim() : "") || DEFAULT_ECH_DNS,
        },
    };
}
const DEFAULT_CONFIG = {
    uuid: DEFAULT_UUID,
    password: "admin",        // 面板访问密码，默认 admin
    domains: [],               // 优选IP：[{ip, remark}]
    proxyIps: [],              // ProxyIP：[host 或 host:port]
    entries: [],               // 入口地址：[优选IP 或域名]，空 = 本项目域名
    proxies: [],               // 其它代理：[{proxy, remark}]
    globalProxy: false,        // true 只走其它代理；false 优先直连，失败回退其它代理
    subConvertBase: DEFAULT_SUBCONVERTER_BASE,   // 订阅转换服务（subconverter 根地址）
    subConfig: "",                             // 订阅转换配置文件（仅 clash）
    bestIpApi: DEFAULT_BEST_IP_API, autoUpdateBestIp: false,
    proxyApi: DEFAULT_PROXY_API, autoUpdateProxies: false,
    proxyProtocols: SUPPORTED_PROXY_PROTOCOLS,
    protocols: ["vless", "trojan"],
    transports: ["ws"],                        // 传输层，可多选：ws / xhttp / grpc
    grpcMode: "gun",                           // gRPC 模式：gun 单流 / multi 多连接复用一条 HTTP/2
    grpcUA: "",                                // gRPC 客户端 UA，留空用客户端自带
    ech: false, echConfig: { sni: DEFAULT_ECH_SNI, dns: DEFAULT_ECH_DNS },
};

// 归一化成 [{<key>, remark}]，去空；domains 顺带去重，proxies 允许重复（同一条可以挂多个入口）
function normalizeList(arr, key, dedupe) {
    const seen = new Set(), out = [];
    if (!Array.isArray(arr)) return out;
    for (const x of arr) {
        const v = typeof x === "string" ? x.trim() : String((x && x[key]) || "").trim();
        if (!v || (dedupe && seen.has(v))) continue;
        seen.add(v);
        out.push({ [key]: v, remark: typeof x === "string" ? "" : String((x && x.remark) || "").trim() });
    }
    return out;
}
const normalizeDomains = (arr) => normalizeList(arr, "ip", true);
const normalizeProxies = (arr) => normalizeList(arr, "proxy", false);

// 解析其它代理订阅文本：每行 protocol://[user:pass@]host:port#备注，仅保留所选协议类型的节点
function parseProxyApiList(text, protocols) {
    const allow = new Set((Array.isArray(protocols) && protocols.length) ? protocols : SUPPORTED_PROXY_PROTOCOLS);
    const seen = new Set(), out = [];
    for (let line of String(text || "").split(/\r?\n/)) {
        line = line.trim();
        if (!line) continue;
        const hashIdx = line.indexOf("#");
        const proxy = (hashIdx === -1 ? line : line.slice(0, hashIdx)).trim();
        const remark = (hashIdx === -1 ? "" : line.slice(hashIdx + 1)).trim();
        const proto = ((proxy.match(/^([a-z0-9]+):\/\//i) || [])[1] || "").toLowerCase();
        const key = proto === "socks" ? "socks5" : proto;
        if (!key || !allow.has(key) || seen.has(proxy)) continue;
        seen.add(proxy);
        out.push({ proxy, remark });
    }
    return out;
}

// 解析优选IP订阅文本：支持 ip / 域名 / [ipv6]，均可带端口与 #备注
// 例：1.2.3.4:8443#香港、store.ubi.com:443#企业域名、2400:3200::1
const IPV4_RE = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_RE = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))$/;
// 单个条目：[IPv6] / IPv4 / 域名 / 裸 IPv6，可带 :端口
const BEST_HOST_RE = /^(?:\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|[0-9a-fA-F]*:[0-9a-fA-F:]*)(?::\d{1,5})?$/;

// 拆分 host:port，未带端口按 443；裸 IPv6 不会被误当成端口
function splitHostPort(addr) {
    const s = String(addr || "").trim();
    if (s.startsWith("[")) {
        const m = s.match(/^(\[[^\]]+\])(?::(\d{1,5}))?$/);
        if (m) return { host: m[1], port: m[2] ? Number(m[2]) : 443 };
    }
    const i = s.lastIndexOf(":");
    if (i > 0 && s.indexOf(":") === i && /^\d{1,5}$/.test(s.slice(i + 1))) return { host: s.slice(0, i), port: Number(s.slice(i + 1)) };
    return { host: s, port: 443 };
}

// 去掉 IPv6 方括号的 host
const bareHost = (addr) => splitHostPort(addr).host.replace(/^\[|\]$/g, "");

// ProxyIP 写法：host / host:port / [ipv6]:port
// 未写端口时固定 443：它是 443 上的反代服务，按目标端口去连多数连不上
function splitProxyIp(proxyIp) {
    const s = String(proxyIp || "").trim();
    if (s.startsWith("[")) {
        const m = s.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
        if (m) return { host: m[1], port: m[2] ? Number(m[2]) : 443 };
    }
    const i = s.lastIndexOf(":");
    if (i > 0 && s.indexOf(":") === i && /^\d{1,5}$/.test(s.slice(i + 1)))
        return { host: s.slice(0, i), port: Number(s.slice(i + 1)) };
    return { host: s, port: 443 };
}

// 去重键：host:port，域名不分大小写，避免 1.2.3.4 与 1.2.3.4:443 生成两个同样的节点
const bestKey = (addr) => `${bareHost(addr).toLowerCase()}:${splitHostPort(addr).port}`;

// 条目是 IP 还是域名，用于区分「优选IP」「优选域名」
const isIpHost = (addr) => { const h = bareHost(addr); return IPV4_RE.test(h) || IPV6_RE.test(h); };

function parseBestIpList(text) {
    const seen = new Set(), out = [];
    const addOne = (raw) => {
        raw = String(raw || "").trim();
        if (!raw) return;
        const hashIdx = raw.indexOf("#");
        const ip = (hashIdx === -1 ? raw : raw.slice(0, hashIdx)).trim();
        const remark = (hashIdx === -1 ? "" : raw.slice(hashIdx + 1)).trim();
        if (!BEST_HOST_RE.test(ip)) return;
        const port = splitHostPort(ip).port;
        if (!(port > 0 && port <= 65535)) return;
        const key = bestKey(ip);
        if (seen.has(key)) return;
        seen.add(key);
        out.push({ ip, remark });
    };
    for (const line of String(text || "").split(/\r?\n/)) {
        const l = line.trim();
        if (!l || l.startsWith("//") || l.startsWith(";")) continue;
        // 整行形如 host[:端口][#备注]：备注允许含空格，整行当一个条目
        if (BEST_HOST_RE.test(l.split("#")[0].trim())) { addOne(l); continue; }
        // 同一行多个条目：按空白/逗号切分
        for (const token of l.split(/[\s,]+/)) addOne(token);
    }
    return out;
}

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

// 无条件补 dns 段：subconverter 不输出 dns，交给客户端默认行为就是明文查运营商 DNS
function ensureClashDns(clashYaml) {
    let yaml = clashYaml.replace(/mode:\s*Rule\b/g, "mode: rule");
    if (!/^dns:\s*(?:\n|$)/m.test(yaml)) yaml = CLASH_BASE_DNS + yaml;
    return yaml;
}

function clashEchHotPatch(clashYaml, { uuid, echSni, echDns, hosts }) {
    if (!uuid) return clashYaml;
    const echEnabled = Boolean(echSni || echDns);
    const hostList = Array.isArray(hosts) ? [...hosts] : [];
    if (echSni && !hostList.includes(echSni)) hostList.push(echSni);
    let yaml = ensureClashDns(clashYaml);

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

// subconverter 能把 VLESS 的 xhttp 原样带出来，但 trojan 会丢掉传输层，
// 返回前按节点名补齐 network 与对应的 opts（xhttp / grpc）；多选传输时每个节点各自补
function clashTransportHotPatch(clashYaml, { host, byLabel, grpcUA }) {
    if (!byLabel || !byLabel.size) return clashYaml;
    const ua = typeof grpcUA === "string" ? grpcUA.trim() : "";
    const patched = clashYaml.replace(/^[ \t]*-[ \t]*\{[^\n]*\}[ \t]*$/gm, (line) => {
        const m = line.match(/name:\s*("([^"]*)"|([^,}]+))/);
        if (!m) return line;
        const label = (m[2] !== undefined ? m[2] : m[3] || "").trim();
        const info = byLabel.get(label);
        if (!info || info.transport === "ws") return line;
        const { transport, path } = info;
        // 已经是 grpc 的节点只需要补 UA（subconverter 能带回 network / service-name，但带不出 UA）
        if (transport === "grpc" && ua && /network:\s*grpc/.test(line)) {
            if (/grpc-user-agent/.test(line)) return line;
            if (/grpc-opts:\s*\{/.test(line))
                return line.replace(/grpc-opts:\s*\{/, `grpc-opts: {grpc-user-agent: ${JSON.stringify(ua)}, `);
            return line.replace(/\}$/, `, grpc-opts: {grpc-user-agent: ${JSON.stringify(ua)}}}`);
        }
        if (new RegExp(`network:\\s*${transport}\\b`).test(line)) return line;
        // mihomo 的 path 按字面值用，query 只会被当成路径的一部分，这里直接去掉；
        // gRPC 服务名同理去掉前导斜杠，否则拼出 //xxx/Tun
        const clashPath = transport === "xhttp" ? path.split("?")[0] : path.replace(/^\/+/, "");
        const optsOf = transport === "grpc"
            ? `grpc-opts: {grpc-service-name: ${JSON.stringify(clashPath)}${ua ? `, grpc-user-agent: ${JSON.stringify(ua)}` : ""}}`
            : `xhttp-opts: {path: ${JSON.stringify(clashPath)}, host: ${JSON.stringify(host)}, mode: stream-one}`;
        if (/network:\s*\w+/.test(line)) {
            return line
                .replace(/network:\s*\w+/, `network: ${transport}`)
                .replace(/,?\s*\w+-opts:\s*\{[^{}]*\}/g, "")
                .replace(/\}$/, `, ${optsOf}}`);
        }
        return line.replace(/\}$/, `, network: ${transport}, ${optsOf}}`);
    });
    // subconverter 会把 Xray 的 mode 参数翻成 grpc-mode，mihomo 没有这个字段，留着只会干扰
    return patched.replace(/,?\s*grpc-mode:\s*[A-Za-z0-9_-]+/g, "");
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
const PANEL_AUTH_RE = /(?:^|;\s*)panel_auth=([^;]+)/;

// 从 cookie 或 URL query 里取 session UUID，都没有返回 null
function getSessionUUID(req, url) {
    if (url) {
        const p = url.searchParams.get("pwd") || url.searchParams.get("uuid");
        if (p) return p;
    }
    const m = (req.headers.get("cookie") || "").match(SESSION_COOKIE_RE);
    return m ? m[1] : null;
}

// ===================== 面板登录态（PASSWORD） =====================
// 面板访问权限改用 PASSWORD（环境变量或基础配置里保存的 password），
// 与「节点/订阅用的 UUID」解耦：UUID 仍决定节点身份与订阅，密码只决定谁能打开面板。
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - s.length % 4) % 4)), (c) => c.charCodeAt(0));

async function panelAuthMac(boot, body) {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(boot)),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
    return new Uint8Array(sig).slice(0, 16);
}

// 签发一个面板登录 token：body = 4 字节过期时间(秒) + 12 字节随机数，签名后 base64url
async function makePanelToken(boot, expAt) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const body = new Uint8Array(16);
    new DataView(body.buffer).setUint32(0, Math.ceil(expAt / 1000), false);
    body.set(nonce, 4);
    const mac = await panelAuthMac(boot, new TextDecoder().decode(body));
    const token = new Uint8Array(16 + mac.length);
    token.set(body); token.set(mac, 16);
    return b64url(token);
}

async function verifyPanelToken(token, boot) {
    if (typeof token !== "string" || !token) return false;
    let raw;
    try { raw = unb64url(token); } catch { return false; }
    if (raw.byteLength !== 32) return false;
    const body = raw.slice(0, 16);
    const sig = raw.slice(16);
    const exp = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(0, false);
    if (exp <= Math.floor(Date.now() / 1000)) return false;
    const want = await panelAuthMac(boot, new TextDecoder().decode(body));
    let diff = 0;
    for (let i = 0; i < want.length; i++) diff |= sig[i] ^ want[i];
    return diff === 0;
}

// 面板登录态是否有效：验 panel_auth 签名 token
async function isPanelAuthed(req, url, cfg, env) {
    const cookie = req.headers.get("cookie") || "";
    const authToken = (cookie.match(PANEL_AUTH_RE) || [])[1];
    if (authToken) {
        const boot = getPanelBoot(env, cfg);
        if (await verifyPanelToken(authToken, boot)) return true;
    }
    return false;
}

// 面板密码：优先基础配置里保存的 password，其次环境变量 PASSWORD，都没有则默认 admin
function getPanelPassword(env, cfg) {
    const saved = typeof cfg.password === "string" ? cfg.password.trim() : "";
    if (saved) return saved;
    const envPw = typeof env?.PASSWORD === "string" ? env.PASSWORD.trim() : "";
    if (envPw) return envPw;
    return "admin";
}

// 签名密钥：绑定当前生效密码，改密码后旧 token 自动失效
function getPanelBoot(env, cfg) {
    return getPanelPassword(env, cfg);
}

// 配置读缓存。隧道每条连接都要读一次配置，测速时几十条并发一起读，
// 排队等 KV 的时间会算进客户端看到的握手时间里（表现就是延迟 -1 或数值偏大）。
// 缓存 3 秒，面板保存时清掉，改动照旧即时生效
let cfgCache = null;
let cfgCacheAt = 0;
const CFG_TTL_MS = 3000;

async function getUserConfig(env) {
    if (cfgCache && Date.now() - cfgCacheAt < CFG_TTL_MS) return cfgCache;
    const fallback = { ...DEFAULT_CONFIG };
    // SUBCONVERTER_BASE 环境变量作为「部署级默认值」：存储里没有 subConvertBase 时生效。
    // 面板上保存过一次之后以面板里的值为准。
    const envBase = normalizeServiceBase(env?.SUBCONVERTER_BASE);
    if (envBase) fallback.subConvertBase = envBase;
    try {
        const cfg = await env.JKPanel?.get("user_config", "json");
        const m = cfg || {};
        m.domains = normalizeDomains(m.domains);
        // 旧单值迁移：s5 → proxies；proxyIp → proxyIps
        if (!Array.isArray(m.proxies)) {
            m.proxies = (typeof m.s5 === "string" && m.s5.trim()) ? [{ proxy: m.s5.trim(), remark: "" }] : [];
        } else {
            m.proxies = normalizeProxies(m.proxies);
        }
        if (!Array.isArray(m.proxyIps)) {
            m.proxyIps = (typeof m.proxyIp === "string" && m.proxyIp.trim()) ? [m.proxyIp.trim()] : [];
        } else {
            m.proxyIps = m.proxyIps.map((x) => String(x || "").trim()).filter(Boolean);
        }
        m.entries = (Array.isArray(m.entries) ? m.entries : []).map((x) => String(x || "").trim()).filter(Boolean);
        m.globalProxy = !!m.globalProxy;
        m.bestIpApi = m.bestIpApi || DEFAULT_BEST_IP_API;
        m.subConvertBase = normalizeServiceBase(m.subConvertBase) || fallback.subConvertBase;
        m.subConfig = normalizeSubConfig(m.subConfig);
        m.autoUpdateBestIp = !!m.autoUpdateBestIp;
        m.proxyApi = (typeof m.proxyApi === "string" && m.proxyApi.trim()) || DEFAULT_PROXY_API;
        m.autoUpdateProxies = !!m.autoUpdateProxies;
        m.proxyProtocols = (Array.isArray(m.proxyProtocols) && m.proxyProtocols.length) ? m.proxyProtocols : SUPPORTED_PROXY_PROTOCOLS;
        if (!Array.isArray(m.protocols) || !m.protocols.length) m.protocols = ["vless", "trojan"];
        // 旧配置只有单个 transport，读出来时统一成数组
        m.transports = normalizeTransports(m);
        m.ech = !!m.ech;
        if (!m.echConfig || typeof m.echConfig !== "object" || Array.isArray(m.echConfig)) m.echConfig = {};
        let echSni = typeof m.echConfig.sni === "string" ? m.echConfig.sni.trim() : "";
        let echDns = typeof m.echConfig.dns === "string" ? m.echConfig.dns.trim() : "";
        m.echConfig.sni = echSni || DEFAULT_ECH_SNI;
        m.echConfig.dns = echDns || DEFAULT_ECH_DNS;
        m.password = (typeof m.password === "string" && m.password.trim()) || DEFAULT_CONFIG.password;
        // 旧 domain 单值并入 domains
        const d = (m.domain || "").trim();
        if (d && !m.domains.some((x) => x.ip === d)) m.domains.unshift({ ip: d, remark: "" });
        cfgCache = { ...fallback, ...m };
        cfgCacheAt = Date.now();
        return cfgCache;
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

// 部分客户端把 path 里的 "?" 编码成 %3F，解析前还原成查询串
function normalizeQueryPath(u){
    if(!u.pathname.includes("%3F")) return u;
    const decoded=decodeURIComponent(u.pathname);
    const index=decoded.indexOf("?");
    if(index!==-1){
        u.search=decoded.slice(index);
        u.pathname=decoded.slice(0,index);
    }
    return u;
}

// ws 与 xhttp 共用：按路径里的 t/d/s/p 决定直连、socks、ProxyIP 的尝试顺序
function resolveRoute(u){
    const pick=(keys)=>{
        for(const k of keys){
            const v=u.searchParams.get(k);
            if(v!==null) return v;
        }
        return null;
    };
    const tval=pick(["t","m","type","mode"]);
    const mode=({d:"direct",s:"s5",p:"parallel"})[tval]||"parallel";
    const s5Param=pick(["s","socks","proxy"]);
    const proxyParam=pick(["p","ip","proxyip"]);
    const proxyConfig=s5Param?parseProxyAddress(s5Param):null;
    const PROXY_IP=proxyParam?String(proxyParam):null;
    const getOrder=()=>{
        // t 已经写明回退方式时按它走，不去猜查询键的顺序
        if(tval==="dp") return PROXY_IP?["direct","proxy"]:["direct"];
        if(tval==="ds") return proxyConfig?["direct","s5"]:["direct"];
        if(mode==="s5") return ["s5"];
        const order=[];
        for(const pair of u.search.slice(1).split("&")){
            const key=pair.split("=")[0];
            if(["d","dir","direct"].includes(key)) order.push("direct");
            if(["s","socks","proxy"].includes(key)) order.push("s5");
            if(["p","ip","proxyip"].includes(key)) order.push("proxy");
        }
        if(order.length===0&&PROXY_IP) return ["proxy","direct"];
        return order.length?order:["direct"];
    };
    return {mode,proxyConfig,PROXY_IP,getOrder};
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
            head=concatBytes(head,value);
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

const connectDirect=async(hostname,portNum,data)=>{
    const sock=connect({hostname,port:portNum});
    await sock.opened;
    // 首包可能刚好被头部吃光，空数据不写，避免零长度写入报错
    if(data&&data.byteLength){
        const w=sock.writable.getWriter();
        await w.write(data);
        w.releaseLock();
    }
    return sock;
};
const connectStreams=async(remoteSocket,webSocket,headerData,retryFunc,userCfg)=>{
    let header=headerData,hasData=false,dataPromiseResolve;
    const dataPromise=new Promise((resolve)=>(dataPromiseResolve=resolve));
    const timeoutId=setTimeout(()=>{if(!hasData) dataPromiseResolve(false);},100);
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
            if(type==="proxy"&&proxyIp){const p=splitProxyIp(proxyIp);return await connectDirect(p.host,p.port,payload);}
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

// ---------- XHTTP（stream-one）----------
// 地址字段：VLESS 的 atyp（1=ipv4,2=域名,3=ipv6）和 Trojan（1=ipv4,3=域名,4=ipv6）编号不同，先统一成类型名
const XHTTP_ATYP = { vless: { 1: "ipv4", 2: "domain", 3: "ipv6" }, trojan: { 1: "ipv4", 3: "domain", 4: "ipv6" } };
function readXhttpAddr(b, pos, kind) {
    if (kind === "ipv4") {
        if (b.byteLength < pos + 4) return null;
        return { addr: `${b[pos]}.${b[pos + 1]}.${b[pos + 2]}.${b[pos + 3]}`, pos: pos + 4 };
    }
    if (kind === "domain") {
        if (b.byteLength < pos + 1) return null;
        const len = b[pos];
        if (b.byteLength < pos + 1 + len) return null;
        return { addr: new TextDecoder().decode(b.slice(pos + 1, pos + 1 + len)), pos: pos + 1 + len };
    }
    if (b.byteLength < pos + 16) return null;
    const dv = new DataView(b.buffer, b.byteOffset + pos, 16), parts = [];
    for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
    return { addr: parts.join(":"), pos: pos + 16 };
}

const isHexByte = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);

// 上行是连续字节流，首包可能被切在两个 chunk 之间：数据不够返回 need，确定不是本协议返回 bad
function parseXhttpHead(raw, uuid) {
    const b = new Uint8Array(raw);
    const need = { state: "need" }, bad = { state: "bad" };
    if (!b.byteLength) return need;

    // 首字节定协议：VLESS 版本号固定 0，Trojan 口令首字符是十六进制
    if (b[0] === 0) {
        // VLESS：ver + uuid(16) + optLen + opt + cmd + port + atyp + addr
        if (b.byteLength < 17) return need;
        const hex = uuid.replace(/-/g, "").toLowerCase();
        for (let i = 0; i < 16; i++) {
            if (b[1 + i].toString(16).padStart(2, "0") !== hex.substr(i * 2, 2)) return bad;
        }
        if (b.byteLength < 18) return need;
        let pos = 18 + b[17];
        if (b.byteLength < pos + 3) return need;
        const cmd = b[pos], port = (b[pos + 1] << 8) | b[pos + 2];
        if (cmd !== 1 && cmd !== 2) return bad;
        pos += 3;
        if (b.byteLength < pos + 1) return need;
        const kind = XHTTP_ATYP.vless[b[pos]];
        if (!kind) return bad;
        const r = readXhttpAddr(b, pos + 1, kind);
        if (!r) return need;
        return { state: "ok", isTrojan: false, hostname: r.addr, port, isUDP: cmd === 2, offset: r.pos };
    }

    // Trojan：56 位十六进制口令 + CRLF + cmd + atyp + addr + port + CRLF
    for (let i = 0, n = Math.min(b.byteLength, 56); i < n; i++) {
        if (!isHexByte(b[i])) return bad;
    }
    if (b.byteLength < 60) return need;
    if (b[56] !== 0x0d || b[57] !== 0x0a) return bad;
    if (new TextDecoder().decode(b.slice(0, 56)).toLowerCase() !== trojanpwd(uuid).toLowerCase()) return bad;
    const cmd = b[58], at = b[59];
    if (cmd !== 1 && cmd !== 3) return bad;
    const kind = XHTTP_ATYP.trojan[at];
    if (!kind) return bad;
    const r = readXhttpAddr(b, 60, kind);
    if (!r) return need;
    if (b.byteLength < r.pos + 4) return need;
    const port = (b[r.pos] << 8) | b[r.pos + 1];
    if (b[r.pos + 2] !== 0x0d || b[r.pos + 3] !== 0x0a) return bad;
    return { state: "ok", isTrojan: true, hostname: r.addr, port, isUDP: cmd === 3, offset: r.pos + 4 };
}

// xhttp 与 gRPC 共用：按 t/d/s/p 决定的顺序连目标，首包一起带过去。
// 拨通就用（直连 → ProxyIP / 其它代理），连不上立刻换下一跳，全失败才算失联。
const DIAL_TIMEOUT_MS = 4000;

const dial = (make, ms) =>
    new Promise((resolve) => {
        let done = false;
        const timer = setTimeout(() => {
            if (done) return;
            done = true;
            resolve(null);
        }, ms);
        make().then(
            (sock) => {
                if (done) { try { sock.close(); } catch {} return; }
                done = true;
                clearTimeout(timer);
                resolve(sock);
            },
            () => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                resolve(null);
            },
        );
    });

const dialerFor = (type, head, opts, payload) => {
    if (type === "direct") return () => connectDirect(head.hostname, head.port, payload);
    if (type === "s5" && opts.proxyConfig) return () => connectViaProxy(opts.proxyConfig, head.hostname, head.port, payload);
    if (type === "proxy" && opts.PROXY_IP) {
        const p = splitProxyIp(opts.PROXY_IP);
        return () => connectDirect(p.host, p.port, payload);
    }
    return null;
};

// 按顺序拨，拨通就用：连不上立刻换下一跳，连上就把流直接交出去，不再等数据
async function openRoute(head, opts, payload) {
    for (const type of opts.getOrder()) {
        const make = dialerFor(type, head, opts, payload);
        if (!make) continue;
        const sock = await dial(make, DIAL_TIMEOUT_MS);
        if (sock) return { sock, reader: sock.readable.getReader() };
    }
    return null;
}

// ---------- gRPC ----------
// 帧格式：5 字节头（1 字节压缩标志 + 4 字节大端长度）+ 消息体，消息体是 protobuf 的字段 1（0x0a + 变长长度 + 数据）
function grpcFrame(chunk) {
    const varint = [];
    let n = chunk.byteLength >>> 0;
    while (n > 127) { varint.push((n & 0x7f) | 0x80); n >>>= 7; }
    varint.push(n);
    const msgLen = 1 + varint.length + chunk.byteLength;
    const frame = new Uint8Array(5 + msgLen);
    frame[1] = (msgLen >>> 24) & 0xff;
    frame[2] = (msgLen >>> 16) & 0xff;
    frame[3] = (msgLen >>> 8) & 0xff;
    frame[4] = msgLen & 0xff;
    frame[5] = 0x0a;
    frame.set(varint, 6);
    frame.set(chunk, 6 + varint.length);
    return frame;
}

function grpcUnwrap(payload) {
    if (payload.byteLength < 2 || payload[0] !== 0x0a) return payload;
    let pos = 1, shift = 0;
    while (pos < payload.byteLength) {
        const cur = payload[pos++];
        if ((cur & 0x80) === 0) return payload.subarray(pos);
        shift += 7;
        if (shift > 35) break;
    }
    return payload;
}

// gRPC 帧可能一次只来半帧，也可能一个 chunk 里挤着几帧，边收边切
function grpcSlicer() {
    let pending = new Uint8Array(0);
    return (chunk) => {
        pending = pending.byteLength ? concatBytes(pending, chunk) : new Uint8Array(chunk);
        const out = [];
        while (pending.byteLength >= 5) {
            const len = 5 + (((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4]);
            if (pending.byteLength < len) break;
            const payload = grpcUnwrap(pending.subarray(5, len));
            pending = pending.subarray(len);
            if (payload.byteLength) out.push(payload);
        }
        return out;
    };
}

// 隧道传输的回退方式写在路径最后一段：d、p-<base64url>、s-<base64url>，
// 前面加 d 表示先直连、失败再回退（dp- / ds-）
// gRPC 客户端实际请求的是 <服务名>/Tun（multi 模式为 /TunMulti），所以要先去掉这个方法名；
// 服务名里的 / 会被客户端编码成 %2F 发出来，不还原就整段拼在一起，回退信息全丢
function grpcRoute(u) {
    let path = u.pathname;
    if (path.includes("%")) {
        try { path = decodeURIComponent(path); } catch {}
    }
    const segs = path.split("/").filter(Boolean);
    if (/^tun(multi)?$/i.test(segs[segs.length - 1] || "")) segs.pop();
    for (let i = segs.length - 1; i >= 0; i--) {
        const seg = segs[i];
        if (seg === "d") return { getOrder: () => ["direct"] };
        const m = /^(d?)([ps])-(.+)$/.exec(seg);
        if (!m) continue;
        const val = b64urlDec(m[3]);
        if (!val) continue;
        const first = m[1] === "d";
        if (m[2] === "p") return { PROXY_IP: val, getOrder: () => (first ? ["direct", "proxy"] : ["proxy", "direct"]) };
        const cfg = parseProxyAddress(val);
        if (cfg) return { proxyConfig: cfg, getOrder: () => (first ? ["direct", "s5"] : ["s5"]) };
    }
    return null;
}

// 下行直通用的管道：Workers 里 IdentityTransformStream 不做内部分块攒包，
// 写进去就出流，首字节不会被拖；本地跑不到时退化成普通 TransformStream
const makePipe = () =>
    typeof IdentityTransformStream !== "undefined" ? new IdentityTransformStream() : new TransformStream();

// 隧道请求的路由：路径段优先（xhttp 混淆、gRPC 都用这种），老订阅仍然读查询串
const tunnelRoute=(u)=>grpcRoute(u)||resolveRoute(u);

// xhttp 与 gRPC 只差一层外壳：xhttp 是裸字节流，gRPC 每段数据套 5 字节帧头 + protobuf 包装。
// 上下行都在同一个 POST 里跑：请求体灌进 socket，socket 的可读流当响应体吐出去。
async function handleTunnel(req, userConfig, opts, mode) {
    if (!req.body) return new Response("bad request", { status: 400 });
    let isGrpc = mode === "grpc";
    const reader = req.body.getReader();
    let slice = isGrpc ? grpcSlicer() : (chunk) => [chunk];
    let wrap = isGrpc ? grpcFrame : (chunk) => chunk;

    let sock = null;
    const reject = (status) => {
        reader.cancel().catch(() => {});
        try { sock && sock.close(); } catch {}
        return new Response("bad request", { status });
    };

    // 首包可能跨 chunk（gRPC 还跨帧），攒到能解析出目标为止
    let headBuf = new Uint8Array(0), rawBuf = new Uint8Array(0), head = { state: "need" };
    while (head.state === "need") {
        let step;
        try { step = await reader.read(); } catch { break; }
        if (step.done) break;
        if (!step.value || !step.value.byteLength) continue;
        rawBuf = rawBuf.byteLength ? concatBytes(rawBuf, step.value) : new Uint8Array(step.value);
        // 同一次读到的后续帧可能已经是正文，解析出目标后仍要并进首包，不能丢
        let parsed = false;
        for (const seg of slice(step.value)) {
            headBuf = headBuf.byteLength ? concatBytes(headBuf, seg) : seg;
            if (headBuf.byteLength > 16384) return reject(400);
            if (parsed) continue;
            head = parseXhttpHead(headBuf, userConfig.uuid);
            if (head.state !== "need") parsed = true;
        }
        if (parsed) break;
    }
    // 客户端外壳不一定和路径判定一致（有的 gRPC 不带 /Tun，有的 xhttp 不认 extra），
    // 首包解不出目标时换另一种外壳再解一次，免得整条链路直接 400
    if (head.state !== "ok" && rawBuf.byteLength) {
        const altBuf = isGrpc ? rawBuf
            : grpcSlicer()(rawBuf).reduce((a, b) => concatBytes(a, b), new Uint8Array(0));
        const alt = altBuf.byteLength ? parseXhttpHead(altBuf, userConfig.uuid) : { state: "bad" };
        if (alt.state === "ok" && !alt.isUDP) {
            isGrpc = !isGrpc;
            slice = isGrpc ? grpcSlicer() : (chunk) => [chunk];
            wrap = isGrpc ? grpcFrame : (chunk) => chunk;
            head = alt;
            headBuf = altBuf;
        }
    }
    // 这条链路不承载 UDP，拒掉后客户端会自己回落 TCP
    if (head.state !== "ok" || head.isUDP) return reject(400);

    // 首包里没被头部吃掉的正文，每条候选连接都要原样再发一次
    const payload = headBuf.subarray(head.offset);
    // 握手不等建连：先回响应头，连接和回退都在流里跑
    const route = openRoute(head, opts, payload);

    // 下行走直通管道，写完就出流；普通 ReadableStream 会先把包攒住，首字节出不来
    const pump = makePipe();
    (async () => {
        const w = pump.writable.getWriter();
        const put = (chunk) => w.write(chunk).catch(() => {});
        try {
            // VLESS 要求先回 [版本号, 附加长度]，Trojan 不用
            if (!head.isTrojan) await put(wrap(new Uint8Array([0, 0])));
            const r = await route;
            if (!r) return;
            sock = r.sock;
            for (;;) {
                const { done, value } = await r.reader.read();
                if (done) break;
                if (value && value.byteLength) await put(wrap(value));
            }
        } catch {}
        try { await w.close(); } catch {}
        try { sock && sock.close(); } catch {}
    })();

    // 上行：请求体继续灌进 socket，读完只关写端，不影响下行
    (async () => {
        let w = null;
        try {
            const r = await route;
            if (!r) { try { reader.cancel(); } catch {} return; }
            w = r.sock.writable.getWriter();
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                if (!value || !value.byteLength) continue;
                for (const seg of slice(value)) await w.write(seg);
            }
        } catch {}
        try { w && (await w.close()); } catch {}
    })();

    // xhttp 回包也带上标识头，回包看着像一个普通 URL，扫描器无从判断这是代理
    const tag = isGrpc ? null : xhttpTag(userConfig && userConfig.uuid);
    return new Response(pump.readable, {
        status: 200,
        headers: {
            "content-type": isGrpc ? "application/grpc" : "application/octet-stream",
            ...(isGrpc ? { "grpc-status": "0" } : {}),
            ...(tag ? { [tag[0]]: `https://x.invalid/?${tag[1]}=${randPad(120 + Math.floor(Math.random() * 780))}` } : {}),
            "cache-control": "no-store",
            "x-accel-buffering": "no",
        },
    });
}

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

        // 隧道传输（xhttp / gRPC）把回退方式写进路径段：
        // d = 只直连，p-/s- = 只走 ProxyIP / 其它代理，dp-/ds- = 先直连，失败再回退
        const routeSeg = (t, p, s) => {
            const tail = p ? "p-" + b64urlEnc(p) : s ? "s-" + b64urlEnc(s) : "";
            if (!tail) return "d";
            return t === "dp" || t === "ds" ? "d" + tail : tail;
        };
        // xhttp 与 gRPC 的路由都放在路径最后一段，路径本身不带查询串：
        // xhttp 开了混淆后查询串会被客户端搬进请求头，路径里再带 ? 只会让各客户端拼出不同的结果
        const buildPathFor = (transport, t, d, s, p) =>
            transport === "ws" ? buildPath(t, d, s, p) : `${getPath()}/${routeSeg(t, p, s)}`;

        // 传输层参数：ws 走 WebSocket；xhttp 走 stream-one（上下行共用一条 HTTP 流）；grpc 走 gRPC 双向流
        // gRPC 的 mode 只对 Xray 系客户端生效（gun 单流 / multi 多连接复用一条 HTTP/2）
        // xhttp 带 extra：客户端会用头里的标识串走混淆，服务端也靠它区分 xhttp 与 gRPC
        const transportQuery = (transport, grpcMode = "gun", uuid = "") =>
            transport === "xhttp" ? `type=xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xhttpExtra(uuid)))}`
                : transport === "grpc" ? `type=grpc&mode=${grpcMode === "multi" ? "multi" : "gun"}`
                    : "type=ws";
        // gRPC 的服务名代替 host/path，其余传输仍然是 host + path
        // 服务名去掉前导斜杠：客户端自己会拼成 /<服务名>/Tun，带着前导的会拼出 //xxx 双斜杠
        // 服务名不加百分号编码：转换服务对 trojan 的 serviceName 不做解码，编过的会原样带进节点
        const pathParam = (transport, rawPathQuery, workerHost) =>
            transport === "grpc"
                ? `serviceName=${rawPathQuery.replace(/^\/+/, "")}&authority=${workerHost}`
                : `host=${workerHost}&path=${encodeURIComponent(rawPathQuery)}`;
        const buildUri = (proto, rawPathQuery, uuid, label, workerHost, preferredDomain, port, echParam = "", transport = "ws", grpcMode = "gun") =>
            `${proto}://${uuid}@${preferredDomain}:${port}?${proto === "vless" ? "encryption=none&" : ""}security=tls&sni=${workerHost}&${transportQuery(transport, grpcMode, uuid)}${echParam}&${pathParam(transport, rawPathQuery, workerHost)}${proto === "vless" ? "&fp=chrome" : ""}#${encodeURIComponent(label || preferredDomain)}`;

        // 取 workerHost / 优选IP(domains) / 入口地址(entries)；入口地址为空时用本项目域名
        const getDomains = (request, cfg) => {
            const workerHost = new URL(request.url).hostname;
            // cfg.domains 在 getUserConfig 已归一化，此处仅兜底非数组
            const domains = Array.isArray(cfg.domains) && cfg.domains.length ? cfg.domains : [{ ip: workerHost, remark: "" }];
            const entries = (cfg.entries || []).length ? cfg.entries : [workerHost];
            return { workerHost, domains, entries };
        };

        // 生成基础节点（label/params/addr/port）。params 是 buildPathFor 的 route 参数，
        // 具体路径要等选定的传输层确定后再拼，所以这里不落 raw。
        // 裸 IPv6 补上方括号，否则拼出来的 URI 不合法
        const nodeHost = (h) => (h.includes(":") && !h.startsWith("[") ? `[${h}]` : h);
        const buildNodes = (cfg, lists) => {
            const nodes = [];
            const proxies = cfg.proxies || [];
            const proxyIps = cfg.proxyIps || [];
            for (const d of lists.domains) {
                const a = splitHostPort(d.ip);
                const host = nodeHost(a.host);
                if (proxyIps.length) {
                    // 填了 ProxyIP：只出「优选IP × ProxyIP」节点，不再单独出优选IP直连节点
                    // ProxyIP 只做直连失败后的顶替，跟全局开关无关：永远是先直连，打不通才换它
                    for (const p of proxyIps)
                        nodes.push({ label: d.remark || d.ip, params: ["dp", 1, null, p], addr: host, port: a.port });
                } else {
                    nodes.push({ label: d.remark || d.ip, params: ["d", 1, null, null], addr: host, port: a.port });
                }
            }
            for (const e of lists.entries) {
                const a = splitHostPort(e);
                const host = nodeHost(a.host);
                for (const pr of proxies) {
                    const name = pr.remark || proxyTypeLabel(pr.proxy);
                    // 全局 = 只走其它代理；非全局 = 先直连，失败再回退到它
                    nodes.push(cfg.globalProxy
                        ? { label: name, params: ["s", null, pr.proxy, null], addr: host, port: a.port }
                        : { label: name, params: ["ds", 1, pr.proxy, null], addr: host, port: a.port });
                }
            }
            return nodes;
        };

        // 每个基础节点 × 每个传输层各出一个。传输标记统一写进节点名，
        // 多选时同一备注会出多条，靠名字里的 W/X/G 区分
        const expandNodes = (nodes, transports) => {
            const list = transports.length ? transports : ["ws"];
            const out = [];
            for (const n of nodes) {
                for (const t of list) {
                    out.push({
                        label: n.label,
                        transport: t,
                        raw: buildPathFor(t, ...n.params),
                        addr: n.addr,
                        port: n.port,
                    });
                }
            }
            return out;
        };

        // 节点名：协议-传输 备注，如 `V-W 香港` / `T-G 日本`
        const nodeName = (proto, transport, label) =>
            `${proto}-${TRANSPORT_BADGE[transport] || "W"} ${label}`;

        if (req.headers.get("Upgrade")?.toLowerCase() === "websocket") {
            const u = normalizeQueryPath(new URL(req.url));
            const userConfig = await getUserConfig(env);
            const [client, ws] = Object.values(new WebSocketPair());
            ws.accept();
            ws.binaryType = 'arraybuffer';

            const { mode, proxyConfig, PROXY_IP, getOrder } = resolveRoute(u);

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
                    ? concatBytes(trojanUDPCtx.cache, curr)
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
                                ? concatBytes(rc.cache, cr)
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
                                                const p = splitProxyIp(PROXY_IP);
                                                return await connectDirect(
                                                    p.host,
                                                    p.port,
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
                                            await connectStreams(sock, ws, null, null, userConfig);
                                        }
                                        return;
                                    }
                                    const primary = await tryConnect(order[0]);
                                    if (!primary) {
                                        const backup = await tryNext(1);
                                        if (backup) {
                                            remote = backup;
                                            await connectStreams(backup, ws, null, null, userConfig);
                                        }
                                        return;
                                    }
                                    remote = primary;
                                    const retryFunc =
                                        order.length > 1
                                            ? async () => {
                                                  const backup = await tryNext(1);
                                                  if (backup) {
                                                      try {
                                                          primary.close();
                                                      } catch {}
                                                      remote = backup;
                                                      await connectStreams(
                                                          backup,
                                                          ws,
                                                          null,
                                                          null,
                                                          userConfig,
                                                      );
                                                  }
                                              }
                                            : null;
                                    await connectStreams(primary, ws, null, retryFunc, userConfig);
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

        const url = normalizeQueryPath(new URL(req.url));

        // 代理流量不限定路径：客户端会把服务名、session 段按自己的方式拼进路径，各版本拼法不同，
        // 死盯伪装路径只会让一部分连接 404（表现就是测速 -1、gRPC 直接连不上）。
        // 只把面板自己的接口和首页登录排除掉。
        const panelApi = url.pathname === "/api/config" || url.pathname === "/api/meta" || url.pathname === "/api/fetch-best-ip" || url.pathname === "/api/fetch-proxies";
        const panelPage = url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/login";
        if (req.method === "POST" && req.body && !panelApi && !panelPage) {
            const userConfig = await getUserConfig(env);
            const [tagHead, tagKey] = xhttpTag(userConfig.uuid);
            const padding = xhttpPadding(req, tagHead, tagKey);
            // 真客户端的 padding 串在百位级，太短或过长的一律当扫描
            if (padding && (padding.length < 64 || padding.length > 4096)) {
                return new Response("bad request", { status: 400 });
            }
            // 带 padding 的是 xhttp；剩下按 gRPC 处理，外壳不对时 handleTunnel 会自己换回来
            const isGrpcReq = !padding &&
                (req.headers.get("content-type") || "").toLowerCase().startsWith("application/grpc");
            return await handleTunnel(
                req,
                userConfig,
                (isGrpcReq ? grpcRoute(url) : tunnelRoute(url)) || resolveRoute(url),
                isGrpcReq ? "grpc" : "xhttp",
            );
        }

        if (url.pathname === "/api/fetch-best-ip") {
            const userConfig = await getUserConfig(env);
            let apiUrl = userConfig.bestIpApi || DEFAULT_BEST_IP_API;
            // 面板上未保存的列表优先，避免合并基准与页面不一致
            let currentDomains = userConfig.domains;
            try {
                const body = await req.json();
                if (body.apiUrl) apiUrl = body.apiUrl;
                if (Array.isArray(body.domains)) currentDomains = body.domains;
            } catch {}
            // 面板身份校验用 panel_auth（或旧 session=uuid 兼容）
            if (!(await isPanelAuthed(req, url, userConfig, env))) return json({ error: "请先登录" }, 401);
            
            try {
                const text = await fetchTextWithTimeout(apiUrl, ACCEPT_HTML, AUTO_FETCH_TIMEOUT_MS);
                const ips = parseBestIpList(text);
                if (!ips.length) return json({ success: false, error: "未获取到优选IP/域名" });
                // 与订阅自动拉取同一套合并逻辑：整批替换「优选」条目，保留手动填写的条目
                const domains = mergeBestIps(currentDomains, ips);
                const added = domains.filter((d) => (d.remark || "").startsWith("优选")).length;
                return json({ success: true, added, domains });
            } catch (error) {
                return json({ success: false, error: error.message }, 500);
            }
        }

        if (url.pathname === "/api/fetch-proxies") {
            const userConfig = await getUserConfig(env);
            let apiUrl = userConfig.proxyApi || "";
            let protocols = userConfig.proxyProtocols || SUPPORTED_PROXY_PROTOCOLS;
            let currentProxies = userConfig.proxies || [];
            try {
                const body = await req.json();
                if (body.apiUrl) apiUrl = body.apiUrl;
                if (Array.isArray(body.protocols) && body.protocols.length) protocols = body.protocols;
                if (Array.isArray(body.proxies)) currentProxies = body.proxies;
            } catch {}
            if (!(await isPanelAuthed(req, url, userConfig, env))) return json({ error: "请先登录" }, 401);
            if (!apiUrl) return json({ error: "未配置其它代理 API 地址" }, 400);
            try {
                const text = await fetchTextWithTimeout(apiUrl, ACCEPT_TEXT, AUTO_FETCH_TIMEOUT_MS);
                const fresh = parseProxyApiList(text, protocols);
                if (!fresh.length) return json({ success: false, error: "未获取到其它代理" });
                // 与订阅自动拉取同一套合并逻辑
                const proxies = mergeProxies(currentProxies, fresh);
                const added = proxies.filter((p) => (p.remark || "").startsWith("优选")).length;
                return json({ success: true, added, proxies });
            } catch (error) {
                return json({ success: false, error: error.message }, 500);
            }
        }

        if (url.pathname === "/api/config") {
            const userConfig = await getUserConfig(env);
            if (req.method === "GET") {
                if (!(await isPanelAuthed(req, url, userConfig, env))) return json({ error: "请先登录" }, 401);
                return json(userConfig);
            } else if (req.method === "POST") {
                try {
                    const incoming = await req.json();
                    // 面板身份校验用 panel_auth（或旧 session=uuid 兼容）
                    if (!(await isPanelAuthed(req, url, userConfig, env))) return json({ error: "请先登录" }, 401);
                    const newUUID = typeof incoming.uuid === "string" ? incoming.uuid.trim() : "";
                    if (!newUUID) return json({ error: "UUID不能为空" }, 400);
                    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(newUUID))
                        return json({ error: "UUID格式不正确，需为标准 UUID（8-4-4-4-12 十六进制）" }, 400);
                    if (typeof incoming.subConvertBase === "string" &&
                        incoming.subConvertBase.trim() &&
                        !normalizeServiceBase(incoming.subConvertBase))
                        return json({ error: "订阅转换服务地址格式不正确，需是 http(s):// 开头的服务地址（不要带 ? 参数）" }, 400);
                    if (typeof incoming.subConfig === "string" &&
                        incoming.subConfig.trim() &&
                        !normalizeSubConfig(incoming.subConfig))
                        return json({ error: "配置文件地址格式不正确，需是 http(s):// 开头的 .ini 地址（不要带 ? 参数）" }, 400);
                    let domains = normalizeDomains(incoming.domains);
                    if (incoming.domain) {
                        const d = (incoming.domain + "").trim();
                        if (d && !domains.some((x) => x.ip === d))
                            domains.unshift({ ip: d, remark: "" });
                    }
                    const proxies = (Array.isArray(incoming.proxies) ? incoming.proxies : [])
                        .map((x) => typeof x === "string" ? { proxy: x.trim(), remark: "" } : (x && { proxy: String(x.proxy || "").trim(), remark: String(x.remark || "").trim() }))
                        .filter((x) => x && x.proxy);
                    if (!proxies.length && incoming.s5) proxies.push({ proxy: String(incoming.s5).trim(), remark: "" });
                    const proxyIps = (Array.isArray(incoming.proxyIps) ? incoming.proxyIps : [])
                        .map((x) => String(x || "").trim()).filter(Boolean);
                    if (!proxyIps.length && incoming.proxyIp) proxyIps.push(String(incoming.proxyIp).trim());
                    const entries = (Array.isArray(incoming.entries) ? incoming.entries : [])
                        .map((x) => String(x || "").trim()).filter(Boolean);
                    const normalized = configForStore(incoming, {
                        uuid: newUUID,
                        domains, proxyIps, entries, proxies,
                    });
                    if (env.JKPanel)
                        await env.JKPanel.put("user_config", JSON.stringify(normalized));
                    cfgCache = null;
                    return json({ success: true, message: "配置保存成功" });
                } catch {
                    return json({ error: "配置保存失败" }, 500);
                }
            }
        }

        if (url.pathname === "/sub") {
            const inputUUID = getSessionUUID(req, url);
            if (!inputUUID) return new Response("missing uuid", { status: 400 });
            let userConfig = await getUserConfig(env);
            if (inputUUID !== userConfig.uuid) return new Response("Not Found", { status: 404 });
            // 拉取失败或超时返回 null，沿用手上的配置继续响应
            userConfig = (await maybeAutoUpdate(env, userConfig)) || userConfig;
            const lists = getDomains(req, userConfig);
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
            // "surge&ver=4" 这类带参数的 target 先按 & 截断再取端点
            const 端点名 = String(订阅类型).split("&")[0].trim().toLowerCase();
            const target = SUBCONVERTER_TARGETS[端点名];
            // 端点不支持的传输层直接剔除（surge/loon/quanx 只认 ws，sing-box 没有 xhttp），
            // 一个都不剩时退回 ws，订阅不至于空掉
            const 不可用 = TRANSPORT_UNSUPPORTED[端点名] || [];
            const 可用传输 = userConfig.transports.filter((t) => !不可用.includes(t));
            const nodes = expandNodes(buildNodes(userConfig, lists), 可用传输.length ? 可用传输 : ["ws"]);
            const echParam = buildEchParam(userConfig);
            // 收集所有节点使用的域名（排除纯 IP），用于 ECH nameserver-policy 走 DoH 解析
            const echHosts = [...new Set(
                [lists.workerHost, ...lists.domains.map((d) => d.ip), ...lists.entries]
                    .map((s) => bareHost(s || ""))
                    .filter((h) => h && !isIpHost(h)),
            )];
            const echSni = userConfig.echConfig?.sni || "";
            const echDns = userConfig.echConfig?.dns || "";
            // 节点名 -> {传输层, 原始 path}：clash 转换后补传输层用
            const transportPaths = new Map();
            for (const n of nodes) {
                if (protocols.includes("vless")) {
                    const name = nodeName("V", n.transport, n.label);
                    transportPaths.set(name, { transport: n.transport, path: n.raw });
                    out.push(buildUri("vless", n.raw, userConfig.uuid, name, lists.workerHost, n.addr, n.port || 443, echParam, n.transport, userConfig.grpcMode));
                }
                if (protocols.includes("trojan")) {
                    const name = nodeName("T", n.transport, n.label);
                    transportPaths.set(name, { transport: n.transport, path: n.raw });
                    out.push(buildUri("trojan", n.raw, userConfig.uuid, name, lists.workerHost, n.addr, n.port || 443, echParam, n.transport, userConfig.grpcMode));
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
            // 没有对应输出格式、或转换服务不可用时，统一回这份 base64 节点列表
            const 原始节点列表 = () => new Response(encodedNodes + "\n", {
                status: 200,
                headers: responseHeaders,
            });
            // mixed，以及没有对应输出格式的（quanx / loon 等）：直接返回通用 base64 节点列表
            if (!target) return 原始节点列表();
            // 转换统一交给 subconverter 协议的服务（ZQ-SubApi 就是这层）：节点名单由本面板生成，
            // base64 后放进 POST body，避免节点多时 URL 过长被网关截断。
            const 转换服务 = normalizeServiceBase(userConfig.subConvertBase) || DEFAULT_SUBCONVERTER_BASE;
            const 转换参数 = new URLSearchParams({
                target,
                udp: "true",
                emoji: "false",
                list: "false",
            });
            if (端点名 === "surge") 转换参数.set("ver", "4");
            // 配置文件只对 clash 生效：surge / singbox 的配置结构不同，传过去会被忽略或报错
            if (端点名 === "clash" && userConfig.subConfig) 转换参数.set("config", userConfig.subConfig);
            const 订阅转换URL = `${转换服务}/sub?${转换参数}`;
            // 透传客户端 UA：subconverter 据此判断客户端能力，固定假 UA 会拿到不匹配的输出
            const clientUA = req.headers.get("User-Agent") || "";
            const convertUA = /^[\x20-\x7e]{1,200}$/.test(clientUA) ? clientUA : `ZQ-JKPanel/${端点名}`;
            try {
                const response = await fetch(订阅转换URL, {
                    method: "POST",
                    headers: {
                        "User-Agent": convertUA,
                        Accept: "*/*",
                        "Content-Type": "text/plain; charset=utf-8",
                    },
                    body: encodedNodes,
                    // 转换服务卡住时不把客户端一起拖死，超时直接给节点列表
                    signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout
                        ? AbortSignal.timeout(25000)
                        : undefined,
                });
                // 转换服务异常时退回 base64 节点列表，订阅不至于整条挂掉
                if (!response.ok) return 原始节点列表();
                let 转换后内容 = await response.text();
                // ECH 热补丁：subconverter 会丢掉 URI 里的 ech 参数，返回前按 UUID 补回
                if (端点名 === "clash") {
                    // dns 段与 ECH 无关，任何情况都要补，否则客户端退回明文解析
                    转换后内容 = ensureClashDns(转换后内容);
                    转换后内容 = clashTransportHotPatch(转换后内容, {
                        host: lists.workerHost,
                        byLabel: transportPaths,
                        grpcUA: userConfig.grpcUA,
                    });
                    if (userConfig.ech)
                        转换后内容 = clashEchHotPatch(转换后内容, {
                            uuid: userConfig.uuid,
                            echSni,
                            echDns,
                            hosts: echHosts,
                        });
                    responseHeaders["content-type"] = "application/x-yaml; charset=utf-8";
                } else if (端点名 === "singbox") {
                    if (userConfig.ech)
                        转换后内容 = singboxEchHotPatch(转换后内容, {
                            uuid: userConfig.uuid,
                            echSni,
                        });
                    responseHeaders["content-type"] = "application/json; charset=utf-8";
                }
                return new Response(转换后内容, { status: 200, headers: responseHeaders });
            } catch {
                return 原始节点列表();
            }
        }

        // 面板要的数据：节点列表、订阅地址、默认值、配置预设。
        // 页面是静态文件，拿不到服务端模板变量，所以这些统一从这里取。
        if (url.pathname === "/api/meta") {
            const userConfig = await getUserConfig(env);
            if (!(await isPanelAuthed(req, url, userConfig, env)))
                return json({ error: "unauthorized" }, 401);
            const lists = getDomains(req, userConfig);
            const protocols = Array.isArray(userConfig.protocols) && userConfig.protocols.length
                ? userConfig.protocols : ["vless", "trojan"];
            const echParam = buildEchParam(userConfig);
            const nodes = [];
            for (const n of expandNodes(buildNodes(userConfig, lists), userConfig.transports)) {
                if (protocols.includes("vless"))
                    nodes.push(buildUri("vless", n.raw, userConfig.uuid, nodeName("V", n.transport, n.label), lists.workerHost, n.addr, n.port || 443, echParam, n.transport, userConfig.grpcMode));
                if (protocols.includes("trojan"))
                    nodes.push(buildUri("trojan", n.raw, userConfig.uuid, nodeName("T", n.transport, n.label), lists.workerHost, n.addr, n.port || 443, echParam, n.transport, userConfig.grpcMode));
            }
            return json({
                uuid: userConfig.uuid,
                subUrl: `${url.origin}/sub?pwd=${userConfig.uuid}`,
                nodes,
                presetBase: SUB_CONFIG_BASE,
                presets: SUB_CONFIG_PRESETS.filter(([f]) => f).map(([file, label]) => ({ file, label })),
                defaults: {
                    subConvertBase: DEFAULT_SUBCONVERTER_BASE,
                    proxyApi: DEFAULT_PROXY_API,
                    bestIpApi: DEFAULT_BEST_IP_API,
                    echSni: DEFAULT_ECH_SNI,
                    echDns: DEFAULT_ECH_DNS,
                },
            });
        }

        // ---------- 面板 ----------
        // 页面是静态文件（docs/index.html、docs/login.html），可以放在任意静态托管上，
        // 这里只按域名反代；面板的数据全部走 /api/*，所以页面换域名不影响功能。
        const proxyPanel = async (file) => {
            const base = normalizeServiceBase(env.PANEL_URL) || DEFAULT_PANEL_URL;
            try {
                const res = await fetch(base.replace(/\/$/, "") + file, {
                    headers: { "user-agent": req.headers.get("user-agent") || "" },
                });
                if (!res.ok) return new Response("panel unavailable", { status: 502 });
                return new Response(res.body, {
                    status: 200,
                    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
                });
            } catch {
                return new Response("panel unavailable", { status: 502 });
            }
        };

        if (url.pathname === "/login") {
            const userConfig = await getUserConfig(env);
            if (req.method === "POST") {
                let pwd = null;
                try { pwd = (await req.formData()).get("pwd"); } catch {}
                if (pwd && pwd === getPanelPassword(env, userConfig)) {
                    const token = await makePanelToken(getPanelBoot(env, userConfig), Date.now() + 86400 * 1000);
                    return new Response(null, {
                        status: 303,
                        headers: {
                            "Location": url.origin + "/",
                            "Set-Cookie": `panel_auth=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
                        },
                    });
                }
                return new Response(null, { status: 303, headers: { "Location": url.origin + "/login?e=1" } });
            }
            return proxyPanel("/login.html");
        }

        if (url.pathname === "/" || url.pathname === "/index.html") {
            const userConfig = await getUserConfig(env);
            if (!(await isPanelAuthed(req, url, userConfig, env)))
                return new Response(null, { status: 303, headers: { "Location": url.origin + "/login" } });
            return proxyPanel("/index.html");
        }
        return new Response("Not Found", { status: 404 });
    },
};

const AUTO_FETCH_TIMEOUT_MS = 5000;
const ACCEPT_HTML = "text/html,application/xhtml+xml,application/xml;";
const ACCEPT_TEXT = "text/plain,text/html,application/xhtml+xml,application/xml;";

async function fetchTextWithTimeout(url, accept, ms) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    try {
        const res = await fetch(url, {
            method: 'get',
            headers: { "Accept": accept, "User-Agent": "cmliu/CF-Workers-DD2D" },
            signal: controller.signal,
        });
        if (!res.ok) throw new Error(`API request failed: ${res.status}`);
        return await res.text();
    } finally {
        clearTimeout(timer);
    }
}

// 备注以「优选」开头的是上一次拉取的批次，本次整批替换；不带该字样的视为手动填写，保留
const isPreferredItem = (item) => (item.remark || "").startsWith("优选");

// 手动条目原样保留，自动拉取的整批替换
function mergePreferred(current, fresh, keyOf, makeItem) {
    const manual = current.filter((it) => !isPreferredItem(it));
    const existing = new Set(manual.map(keyOf));
    const auto = [];
    for (const it of fresh) {
        const key = keyOf(it);
        if (!key || existing.has(key)) continue;
        existing.add(key);
        auto.push(makeItem(it));
    }
    return [...manual, ...auto];
}

const mergeBestIps = (domains, ips) =>
    mergePreferred(normalizeDomains(domains), ips, (d) => bestKey(d.ip), (i) => ({ ip: i.ip, remark: isIpHost(i.ip) ? "优选IP" : "优选域名" }));

const mergeProxies = (proxies, fresh) =>
    mergePreferred(normalizeProxies(proxies), fresh, (p) => p.proxy, (p) => ({ proxy: p.proxy, remark: "优选" + p.remark }));

// 未勾选或没填地址时返回 null，不发请求；拉取失败返回空数组，不拖累另一个源
const pullList = (enabled, url, accept, parse) =>
    enabled && url
        ? fetchTextWithTimeout(url, accept, AUTO_FETCH_TIMEOUT_MS)
            .then(parse)
            .catch((e) => { console.error("Auto update failed:", url, e); return []; })
        : null;

// 拉取优选IP与其它代理并回写配置，返回合并后的配置；没有新内容返回 null
async function runAutoUpdate(env, cfg) {
    // 两个源并发拉，各自 5 秒超时，最坏也是 5 秒
    const [ips, fresh] = await Promise.all([
        pullList(cfg.autoUpdateBestIp, cfg.bestIpApi, ACCEPT_HTML, parseBestIpList),
        pullList(cfg.autoUpdateProxies, cfg.proxyApi, ACCEPT_TEXT, (text) => parseProxyApiList(text, cfg.proxyProtocols)),
    ]);

    const domains = ips && ips.length ? mergeBestIps(cfg.domains, ips) : null;
    const proxies = fresh && fresh.length ? mergeProxies(cfg.proxies, fresh) : null;
    if (!domains && !proxies) return null;

    const merged = configForStore(cfg, {
        domains: domains || cfg.domains,
        proxies: proxies || cfg.proxies,
    });
    // 内容没有变化就不写 KV，省掉一次无谓的写
    const changed =
        JSON.stringify(merged.domains) !== JSON.stringify(normalizeDomains(cfg.domains)) ||
        JSON.stringify(merged.proxies) !== JSON.stringify(normalizeProxies(cfg.proxies));
    if (changed && env.JKPanel) {
        await env.JKPanel.put("user_config", JSON.stringify(merged));
        cfgCache = null;
    }
    return merged;
}

// 订阅请求触发。返回合并后的配置供本次响应用，未更新则返回 null
async function maybeAutoUpdate(env, cfg) {
    if (!env || !env.JKPanel) return null;
    try {
        cfg = cfg || (await getUserConfig(env));
        if (!cfg.autoUpdateBestIp && !cfg.autoUpdateProxies) return null;
        return await runAutoUpdate(env, cfg);
    } catch (e) {
        console.error("Error in auto update:", e);
        return null;
    }
}
