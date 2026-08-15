// functions/api/links.js —— 云端自定义链接接口（安全版）
//
// 安全设计：
//   - GET 公开读取（访客）
//   - 写操作（POST/PUT）必须携带正确 x-admin-key 请求头，否则 401
//   - 写入内容严格校验：必须是数组、单条字段长度限制、URL 协议白名单、总量限制
//
// 部署要求：与 config.js 一致（绑定 NAV_DB、配置 ADMIN_KEY）

const KV_KEY = 'custom_links';
const MAX_BODY_BYTES = 256 * 1024; // 256KB
const MAX_LINKS = 200;

export async function onRequest(context) {
    const { request, env } = context;

    if (request.method === 'GET') {
        return handleGet(env);
    }
    if (request.method === 'POST' || request.method === 'PUT') {
        return handleWrite(env, request);
    }
    return json({ ok: false, error: 'Method not allowed' }, 405);
}

async function handleGet(env) {
    try {
        const raw = await env.NAV_DB.get(KV_KEY);
        let links = [];
        if (raw) {
            try {
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) links = parsed;
            } catch (e) {
                // 数据损坏时返回空列表，不把错误暴露给访客
            }
        }
        return json({ ok: true, data: links });
    } catch (e) {
        return json({ ok: false, error: e.message }, 500);
    }
}

async function handleWrite(env, request) {
    // 强制鉴权
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

    if (!Array.isArray(body)) {
        return json({ ok: false, error: '数据格式错误：应为数组' }, 400);
    }

    const clean = [];
    for (const item of body.slice(0, MAX_LINKS)) {
        if (!item || typeof item !== 'object') continue;
        const name = String(item.name || '').trim().slice(0, 100);
        const url = sanitizeUrl(item.url);
        if (name && url) clean.push({ name, url });
    }

    try {
        await env.NAV_DB.put(KV_KEY, JSON.stringify(clean));
        return json({ ok: true, count: clean.length });
    } catch (e) {
        return json({ ok: false, error: e.message }, 500);
    }
}

function sanitizeUrl(u) {
    u = String(u || '').trim().slice(0, 2000);
    if (!/^https?:\/\//i.test(u)) return '';
    return u.replace(/['"\\\r\n]/g, '');
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
