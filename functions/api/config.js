// functions/api/config.js —— 站点全局配置接口（安全版）
//
// 安全设计：
//   - 管理员密码不再存入 KV，改为 Cloudflare 环境变量 ADMIN_KEY
//   - GET 公开读取（壁纸、动态分类），响应中强制剥离 adminPwd 等敏感字段（防历史残留）
//   - 请求头携带 x-admin-key 且正确 → 视为管理员（登录验证用）
//   - 任何写操作（POST/PUT）必须携带正确 x-admin-key，否则 401
//   - 写操作做 JSON 解析、字段白名单、URL 协议校验、大小限制
//
// 部署要求（Cloudflare Pages 控制台 → Settings → Variables and Secrets）：
//   - 绑定 KV 命名空间，变量名 NAV_DB（与 links.js 共用）
//   - 新增环境变量 ADMIN_KEY，值设为你的后台密码（改密码 = 改这个变量）

const KV_KEY = 'site_config';
const MAX_BODY_BYTES = 256 * 1024; // 256KB

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'GET') {
        return handleGet(env, request);
    }
    if (request.method === 'POST' || request.method === 'PUT') {
        return handleWrite(env, request);
    }
    return json({ ok: false, error: 'Method not allowed' }, 405);
}

async function handleGet(env, request) {
    // 携带 x-admin-key 时校验（供前端登录验证；错误 key 直接 401）
    const adminKey = env.ADMIN_KEY;
    const provided = request.headers.get('x-admin-key');
    if (provided && adminKey && provided !== adminKey) {
        return json({ ok: false, error: '未授权' }, 401);
    }
    const authed = !!(provided && adminKey && provided === adminKey);

    try {
        const raw = await env.NAV_DB.get(KV_KEY);
        let data = {};
        if (raw) {
            try { data = JSON.parse(raw); } catch (e) { data = {}; }
        }
        // 强制剥离密码字段，防止历史数据残留泄露
        stripSecrets(data);
        return json({ ok: true, data, authed });
    } catch (e) {
        return json({ ok: false, error: e.message }, 500);
    }
}

async function handleWrite(env, request) {
    // 强制鉴权：没有正确 key 一律拒绝
    const adminKey = env.ADMIN_KEY;
    if (!adminKey) {
        return json({ ok: false, error: '服务端未配置 ADMIN_KEY，禁止写入' }, 500);
    }
    const provided = request.headers.get('x-admin-key');
    if (provided !== adminKey) {
        return json({ ok: false, error: '未授权' }, 401);
    }

    let body;
    try {
        const text = await request.text();
        if (text.length > MAX_BODY_BYTES) {
            return json({ ok: false, error: '数据过大' }, 413);
        }
        body = JSON.parse(text);
    } catch (e) {
        return json({ ok: false, error: 'JSON 解析失败' }, 400);
    }

    // 字段白名单 + 清洗
    const clean = {};
    if (typeof body.wallpaper === 'string') {
        clean.wallpaper = sanitizeUrl(body.wallpaper);
    }
    if (Array.isArray(body.dynamicSections)) {
        clean.dynamicSections = sanitizeSections(body.dynamicSections);
    }
    if (body.layout && typeof body.layout === 'object') {
        clean.layout = sanitizeLayout(body.layout);
    }
    if (Array.isArray(body.fixedSections)) {
        clean.fixedSections = sanitizeFixedSections(body.fixedSections);
    }
    // 任何密码字段一律丢弃：密码只存在于环境变量 ADMIN_KEY
    stripSecrets(body);

    try {
        await env.NAV_DB.put(KV_KEY, JSON.stringify(clean));
        return json({ ok: true });
    } catch (e) {
        return json({ ok: false, error: e.message }, 500);
    }
}

function stripSecrets(obj) {
    if (!obj || typeof obj !== 'object') return;
    delete obj.adminPwd;
    delete obj.admin_pwd;
    delete obj.pwd;
    delete obj.password;
}

function sanitizeUrl(u) {
    u = String(u).trim().slice(0, 2000);
    if (!/^https?:\/\//i.test(u)) return '';
    // 过滤 CSS 注入与控制字符
    return u.replace(/['"\\\r\n]/g, '');
}

function sanitizeSections(sections) {
    const out = [];
    for (const sec of sections.slice(0, 30)) {
        if (!sec || typeof sec !== 'object') continue;
        const title = String(sec.title || '').trim().slice(0, 100);
        if (!title) continue;
        const links = [];
        for (const l of (Array.isArray(sec.links) ? sec.links : []).slice(0, 100)) {
            if (!l || typeof l !== 'object') continue;
            const name = String(l.name || '').trim().slice(0, 100);
            const url = sanitizeUrl(l.url);
            if (name && url) links.push({ name, url });
        }
        out.push({ id: String(sec.id || '').slice(0, 64), title, links });
    }
    return out;
}

// 固定卡片（官网直达/常用工具）配置清洗：
// id 仅允许两张固定卡；标题/图标白名单；链接复用 URL 校验
const FIXED_CARD_IDS = ['card-recommend', 'card-develop'];
function sanitizeFixedSections(secs) {
    const out = [];
    for (const sec of secs.slice(0, 10)) {
        if (!sec || typeof sec !== 'object') continue;
        const id = String(sec.id || '');
        if (!FIXED_CARD_IDS.includes(id)) continue;
        const title = String(sec.title || '').trim().slice(0, 50);
        // 图标只允许 fontawesome class，防 class 注入
        const icon = /^fa-[a-zA-Z0-9-]+$/.test(String(sec.icon || '')) ? String(sec.icon) : '';
        const links = [];
        for (const l of (Array.isArray(sec.links) ? sec.links : []).slice(0, 50)) {
            if (!l || typeof l !== 'object') continue;
            const name = String(l.name || '').trim().slice(0, 100);
            const url = sanitizeUrl(l.url);
            if (name && url) links.push({ name, url });
        }
        out.push({ id, title: title || null, icon, links });
    }
    return out;
}

// 布局配置清洗：所有值白名单 + 数值范围钳制，防注入
function sanitizeLayout(l) {
    const out = {};
    if ([2, 3, 4].includes(Number(l.columns))) out.columns = Number(l.columns);
    if ([16, 32, 48].includes(Number(l.gap))) out.gap = Number(l.gap);
    if ([8, 16, 24].includes(Number(l.radius))) out.radius = Number(l.radius);
    const op = parseFloat(l.opacity);
    if (!isNaN(op) && op > 0) out.opacity = Math.min(1, Math.max(0.2, Math.round(op * 100) / 100));
    out.showFriendLinks = l.showFriendLinks !== false;
    out.useFavicon = l.useFavicon !== false;
    if (['faviconim', 'google', 'yandex', 'direct', 'none'].includes(l.faviconService)) {
        out.faviconService = l.faviconService;
    }
    // 卡片标题图标：key 限卡片 id 格式，value 只允许 fas/far/fab 等 + fa-xxx 的字体图标类
    if (l.cardIcons && typeof l.cardIcons === 'object' && !Array.isArray(l.cardIcons)) {
        const ci = {};
        Object.keys(l.cardIcons).slice(0, 40).forEach(k => {
            const key = String(k).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80);
            const val = String(l.cardIcons[k]).trim().slice(0, 80);
            if (key && /^(fas|far|fab|fa-solid|fa-regular|fa-brands) fa-[a-z0-9-]+$/i.test(val)) ci[key] = val.toLowerCase();
        });
        out.cardIcons = ci;
    }
    if (Array.isArray(l.cardOrder)) {
        out.cardOrder = l.cardOrder.map(s => String(s).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)).filter(Boolean).slice(0, 60);
    }
    if (Array.isArray(l.hiddenCards)) {
        out.hiddenCards = l.hiddenCards.map(s => String(s).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80)).filter(Boolean).slice(0, 60);
    }
    return out;
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
