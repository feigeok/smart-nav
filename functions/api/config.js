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

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
