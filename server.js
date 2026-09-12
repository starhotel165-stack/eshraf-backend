/**
 * اشراف — بک‌اند مستقل (Node.js + Express + Redis)
 * جایگزین Cloudflare Workers برای نسخه‌ی مستقل‌شده‌ی «راوی سوریه»
 *
 * اجرا: node server.js   (متغیرهای محیطی از طریق systemd EnvironmentFile تزریق می‌شن)
 */

const express = require('express');
const crypto = require('crypto');
const { createClient } = require('redis');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY || '';
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || '';
const TELEGRAM_CHANNEL_USERNAME = (process.env.TELEGRAM_CHANNEL_USERNAME || 'syriamonitoring').toLowerCase();
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false'; // پیش‌فرض true (چون پشت HTTPS هستیم)
// آدرس و رمز مشترک Worker واسط رو Cloudflare — برای دورزدن فیلترینگ تلگرام/یوتیوب
const RELAY_URL = (process.env.RELAY_URL || '').replace(/\/$/, '');
const RELAY_SECRET = process.env.RELAY_SECRET || '';

const MAX_STORED_POSTS = 5000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // ۳۰ روز
const AI_TOOL_COOLDOWN_MS = 15 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_SECONDS = 15 * 60; // ۱۵ دقیقه

/* ---------------------------------------------------------------------
   اتصال به Redis
--------------------------------------------------------------------- */
const redis = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6379' });
redis.on('error', (err) => console.error('Redis error:', err));

/* ---------------------------------------------------------------------
   کوکی — پیاده‌سازی دستی و ساده (بدون نیاز به پکیج جدا)
--------------------------------------------------------------------- */
function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    out[key] = decodeURIComponent(val);
  });
  return out;
}

function setCookie(res, name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  const parts = [`${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (COOKIE_SECURE) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

/* ---------------------------------------------------------------------
   هش‌کردن رمز عبور با scrypt (توکار Node، بدون نیاز به پکیج جدا)
--------------------------------------------------------------------- */
function hashPassword(password, saltHex) {
  return new Promise((resolve, reject) => {
    const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({ hash: derivedKey.toString('hex'), salt: salt.toString('hex') });
    });
  });
}

async function verifyPassword(password, saltHex, expectedHashHex) {
  const { hash } = await hashPassword(password, saltHex);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(expectedHashHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/* ---------------------------------------------------------------------
   احراز هویت — نشست با کوکی امن (HttpOnly + Secure + SameSite=Strict)
--------------------------------------------------------------------- */
// کلید هر تب/نوار — برای دسترسی‌دهی جزء‌به‌جزء تو پنل مدیریت کاربران
const ALL_TAB_KEYS = ['live', 'wordcloud', 'youtube', 'archive', 'psyop', 'infographic', 'scenario', 'caption'];

async function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.eshraf_session;
  if (!token) return null;
  const raw = await redis.get(`session:${token}`);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    session.token = token;
    return session;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  getSession(req).then((session) => {
    if (!session) return res.status(401).json({ ok: false, error: 'لطفاً ابتدا وارد شوید.' });
    req.session = session;
    next();
  });
}

function requireAdmin(req, res, next) {
  getSession(req).then((session) => {
    if (!session) return res.status(401).json({ ok: false, error: 'لطفاً ابتدا وارد شوید.' });
    if (session.role !== 'admin') return res.status(403).json({ ok: false, error: 'فقط مدیر کل به این بخش دسترسی دارد.' });
    req.session = session;
    next();
  });
}

// دسترسی به یک تب خاص: مدیر کل همیشه مجازه؛ کاربر عادی فقط اگه تو allowedTabs باشه
function requireTabAccess(tabKey) {
  return (req, res, next) => {
    getSession(req).then((session) => {
      if (!session) return res.status(401).json({ ok: false, error: 'لطفاً ابتدا وارد شوید.' });
      const allowed = session.role === 'admin' || (Array.isArray(session.allowedTabs) && session.allowedTabs.includes(tabKey));
      if (!allowed) return res.status(403).json({ ok: false, error: 'به این بخش دسترسی نداری.' });
      req.session = session;
      next();
    });
  };
}

// دسترسی اگه کاربر حداقل به یکی از چندتا تب دسترسی داشته باشه (مثلاً یه endpoint که هم تو psyop هم تو infographic استفاده می‌شه)
function requireAnyTabAccess(...tabKeys) {
  return (req, res, next) => {
    getSession(req).then((session) => {
      if (!session) return res.status(401).json({ ok: false, error: 'لطفاً ابتدا وارد شوید.' });
      const allowed = session.role === 'admin' || (Array.isArray(session.allowedTabs) && tabKeys.some((t) => session.allowedTabs.includes(t)));
      if (!allowed) return res.status(403).json({ ok: false, error: 'به این بخش دسترسی نداری.' });
      req.session = session;
      next();
    });
  };
}

// محدودیت تلاش ورود (جلوگیری از حمله‌ی brute-force)
async function checkLoginRateLimit(ip) {
  const key = `login_attempts:${ip}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, LOGIN_WINDOW_SECONDS);
  return count <= LOGIN_MAX_ATTEMPTS;
}

app.post('/api/auth/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const allowed = await checkLoginRateLimit(ip);
  if (!allowed) {
    return res.status(429).json({ ok: false, error: 'تعداد تلاش‌های ورود بیش‌ازحد است. چند دقیقه‌ی دیگر دوباره امتحان کن.' });
  }

  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username || !password) return res.status(400).json({ ok: false, error: 'نام‌کاربری و رمز عبور را وارد کن.' });

  const raw = await redis.get(`user:${username}`);
  if (!raw) return res.status(401).json({ ok: false, error: 'نام‌کاربری یا رمز عبور اشتباه است.' });

  const user = JSON.parse(raw);
  const valid = await verifyPassword(password, user.salt, user.hash);
  if (!valid) return res.status(401).json({ ok: false, error: 'نام‌کاربری یا رمز عبور اشتباه است.' });

  const role = user.role === 'admin' ? 'admin' : 'user';
  const allowedTabs = role === 'admin' ? ALL_TAB_KEYS : (Array.isArray(user.allowedTabs) ? user.allowedTabs : []);

  const token = crypto.randomBytes(32).toString('hex');
  await redis.set(`session:${token}`, JSON.stringify({ username: user.username, role, allowedTabs }), { EX: SESSION_TTL_SECONDS });
  setCookie(res, 'eshraf_session', token, SESSION_TTL_SECONDS);

  await redis.del(`login_attempts:${ip}`); // ورود موفق -> شمارنده ریست بشه

  res.json({ ok: true, username: user.username, role, allowedTabs });
});

app.post('/api/auth/logout', async (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.eshraf_session) await redis.del(`session:${cookies.eshraf_session}`);
  clearCookie(res, 'eshraf_session');
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const session = await getSession(req);
  if (!session) return res.status(401).json({ ok: false });
  res.json({ ok: true, username: session.username, role: session.role || 'user', allowedTabs: session.allowedTabs || [] });
});

/* ---------------------------------------------------------------------
   پنل مدیریت کاربران — فقط مدیر کل
--------------------------------------------------------------------- */
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const keys = [];
  for await (const key of redis.scanIterator({ MATCH: 'user:*' })) keys.push(key);

  const users = [];
  for (const key of keys) {
    const raw = await redis.get(key);
    if (!raw) continue;
    const u = JSON.parse(raw);
    users.push({
      username: u.username,
      role: u.role === 'admin' ? 'admin' : 'user',
      allowedTabs: u.role === 'admin' ? ALL_TAB_KEYS : (Array.isArray(u.allowedTabs) ? u.allowedTabs : []),
    });
  }
  users.sort((a, b) => a.username.localeCompare(b.username));
  res.json({ ok: true, users, allTabs: ALL_TAB_KEYS });
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  const allowedTabs = role === 'user' && Array.isArray(req.body.allowedTabs)
    ? req.body.allowedTabs.filter((t) => ALL_TAB_KEYS.includes(t))
    : [];

  if (!username || !password) return res.status(400).json({ ok: false, error: 'نام‌کاربری و رمز عبور الزامی است.' });
  if (password.length < 8) return res.status(400).json({ ok: false, error: 'رمز عبور باید حداقل ۸ کاراکتر باشد.' });

  const existing = await redis.get(`user:${username}`);
  if (existing) return res.status(400).json({ ok: false, error: 'این نام‌کاربری قبلاً استفاده شده است.' });

  const { hash, salt } = await hashPassword(password);
  await redis.set(`user:${username}`, JSON.stringify({ username, hash, salt, role, allowedTabs }));

  res.json({ ok: true });
});

app.patch('/api/admin/users/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  const raw = await redis.get(`user:${username}`);
  if (!raw) return res.status(404).json({ ok: false, error: 'کاربر پیدا نشد.' });

  const user = JSON.parse(raw);
  if (typeof req.body.role === 'string') user.role = req.body.role === 'admin' ? 'admin' : 'user';
  if (Array.isArray(req.body.allowedTabs)) user.allowedTabs = req.body.allowedTabs.filter((t) => ALL_TAB_KEYS.includes(t));

  await redis.set(`user:${username}`, JSON.stringify(user));
  res.json({ ok: true });
});

app.delete('/api/admin/users/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  if (username === req.session.username) return res.status(400).json({ ok: false, error: 'نمی‌توانی حساب خودت را حذف کنی.' });
  await redis.del(`user:${username}`);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------------
   وبهوک تلگرام — دریافت پست جدید از کانال SyriaMonitoring
--------------------------------------------------------------------- */
app.post('/api/telegram-webhook', async (req, res) => {
  const secretHeader = req.headers['x-telegram-bot-api-secret-token'];
  if (!WEBHOOK_SECRET || secretHeader !== WEBHOOK_SECRET) {
    return res.status(401).send('Unauthorized');
  }

  const update = req.body || {};
  const msg = update.channel_post || update.edited_channel_post;
  if (!msg) return res.status(200).send('OK');

  const chatUsername = msg.chat && msg.chat.username ? msg.chat.username.toLowerCase() : null;
  if (chatUsername !== TELEGRAM_CHANNEL_USERNAME) return res.status(200).send('OK - unknown channel');

  const text = msg.text || msg.caption || '';
  if (!text.trim()) return res.status(200).send('OK - empty text');

  const post = {
    id: `${msg.chat.id}_${msg.message_id}`,
    messageId: msg.message_id,
    text,
    date: msg.date * 1000,
    link: msg.chat.username ? `https://t.me/${msg.chat.username}/${msg.message_id}` : null,
  };

  const existingRaw = await redis.get('posts');
  let list = [];
  if (existingRaw) {
    try { list = JSON.parse(existingRaw); } catch { list = []; }
  }

  const idx = list.findIndex((p) => p.id === post.id);
  if (idx >= 0) list[idx] = post;
  else list.unshift(post);

  list.sort((a, b) => b.date - a.date);
  list = list.slice(0, MAX_STORED_POSTS);
  await redis.set('posts', JSON.stringify(list));

  res.status(200).send('OK');
});

/* ---------------------------------------------------------------------
   اسکرپ صفحه‌ی عمومی تلگرام (از طریق واسط Cloudflare) — چون تلگرام
   پیام‌های ارسالی توسط ربات‌های دیگه (مثل Inoreader) رو هیچ‌وقت از
   طریق وبهوک به ما نمی‌ده (محدودیت رسمی خودِ تلگرام)، این روش
   جایگزین برای گرفتن همون پیام‌هاست.
--------------------------------------------------------------------- */
function decodeHtmlEntities(str) {
  return str
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&nbsp;/g, ' ');
}
function stripHtmlTags(html) {
  return decodeHtmlEntities(html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').trim());
}

const SCRAPE_INTERVAL_MS = 3 * 60 * 1000; // حداکثر هر ۳ دقیقه یک‌بار

async function fetchTelegramPreviewHtml(channelUsername) {
  if (!RELAY_URL || !RELAY_SECRET) throw new Error('RELAY_URL یا RELAY_SECRET تنظیم نشده.');
  const scrapeUrl = `${RELAY_URL}/scrape?secret=${encodeURIComponent(RELAY_SECRET)}&channel=${encodeURIComponent(channelUsername)}`;
  const res = await fetch(scrapeUrl);
  if (!res.ok) throw new Error(`واسط اسکرپ خطای ${res.status} برگرداند`);
  return res.text();
}

function parseTelegramPreviewPosts(html) {
  const chunks = html.split('class="tgme_widget_message_wrap').slice(1);
  const posts = [];

  for (const chunk of chunks) {
    const postMatch = chunk.match(/data-post="([^"]+)"/);
    if (!postMatch) continue;
    const textMatch = chunk.match(/class="tgme_widget_message_text js-message_text"[^>]*>([\s\S]*?)<\/div>/);
    const timeMatch = chunk.match(/<time datetime="([^"]+)"/);

    const text = textMatch ? stripHtmlTags(textMatch[1]) : '';
    if (!text) continue;

    posts.push({
      id: postMatch[1],
      messageId: parseInt(postMatch[1].split('/')[1], 10) || 0,
      text,
      date: timeMatch ? new Date(timeMatch[1]).getTime() : Date.now(),
      link: `https://t.me/${postMatch[1]}`,
    });
  }

  return posts;
}

async function scrapeChannelViaRelay() {
  const html = await fetchTelegramPreviewHtml(TELEGRAM_CHANNEL_USERNAME);
  return parseTelegramPreviewPosts(html).map((p) => ({ ...p, id: `scrape_${p.id}` }));
}

async function maybeScrapeChannel() {
  const now = Date.now();
  const lastRaw = await redis.get('scrape_last_at');
  const last = lastRaw ? parseInt(lastRaw, 10) : 0;
  if (now - last < SCRAPE_INTERVAL_MS) return;

  await redis.set('scrape_last_at', String(now)); // فوری ثبت می‌کنیم تا درخواست‌های هم‌زمان دوباره اسکرپ نکنن

  try {
    const scraped = await scrapeChannelViaRelay();
    if (scraped.length === 0) return;

    const existingRaw = await redis.get('posts');
    let list = existingRaw ? JSON.parse(existingRaw) : [];

    for (const post of scraped) {
      const idx = list.findIndex((p) => p.id === post.id);
      if (idx >= 0) list[idx] = post;
      else list.unshift(post);
    }

    list.sort((a, b) => b.date - a.date);
    list = list.slice(0, MAX_STORED_POSTS);
    await redis.set('posts', JSON.stringify(list));
  } catch (e) {
    console.error('خطا در اسکرپ کانال:', e.message);
  }
}

/* ---------------------------------------------------------------------
   کمکی: محاسبه‌ی شروع «امروز» به وقت دمشق (UTC+3، بدون تغییر ساعت تابستانی)
--------------------------------------------------------------------- */
function getDamascusDayStartMs(nowMs) {
  const DAMASCUS_OFFSET_MS = 3 * 60 * 60 * 1000;
  const shifted = new Date(nowMs + DAMASCUS_OFFSET_MS);
  shifted.setUTCHours(0, 0, 0, 0);
  return shifted.getTime() - DAMASCUS_OFFSET_MS;
}
function toDamascusDateString(ms) {
  const DAMASCUS_OFFSET_MS = 3 * 60 * 60 * 1000;
  const shifted = new Date(ms + DAMASCUS_OFFSET_MS);
  return shifted.toISOString().slice(0, 10);
}

/* ---------------------------------------------------------------------
   پوشش زنده اخبار (فقط امروز) + آرشیو (بر اساس تاریخ)
--------------------------------------------------------------------- */
app.get('/api/posts', requireTabAccess('live'), async (req, res) => {
  await maybeScrapeChannel();
  const raw = await redis.get('posts');
  const allPosts = raw ? JSON.parse(raw) : [];
  const now = Date.now();
  const todayStart = getDamascusDayStartMs(now);
  const posts = allPosts.filter((p) => p.date >= todayStart && p.date <= now);
  res.json({ posts });
});

app.get('/api/archive', requireTabAccess('archive'), async (req, res) => {
  await maybeScrapeChannel();
  const dateParam = req.query.date;
  if (!dateParam) return res.json({ posts: [] });
  const raw = await redis.get('posts');
  const allPosts = raw ? JSON.parse(raw) : [];
  const matched = allPosts.filter((p) => toDamascusDateString(p.date) === dateParam);
  res.json({ posts: matched });
});

app.post('/api/admin/clear-posts', requireTabAccess('live'), async (req, res) => {
  await redis.del('posts');
  res.json({ ok: true });
});

/* ---------------------------------------------------------------------
   کمکی مشترک: شمارش کلمات پرتکرار (بدون هوش مصنوعی)
--------------------------------------------------------------------- */
const STOPWORDS = new Set([
  'من', 'تو', 'او', 'ما', 'شما', 'ایشان', 'این', 'آن', 'که', 'را', 'با', 'به', 'از', 'در', 'برای', 'است', 'بود',
  'شد', 'شده', 'می', 'هم', 'یک', 'دو', 'سه', 'و', 'یا', 'اما', 'ولی', 'اگر', 'چون', 'تا', 'بر', 'های', 'ها',
  'علی', 'عن', 'في', 'إلى', 'من', 'على', 'هذا', 'هذه', 'التي', 'الذي', 'كان', 'وكان', 'وقال', 'قال', 'بعد',
  'قبل', 'أن', 'إن', 'لا', 'لم', 'ما', 'مع', 'هو', 'هي', 'كل', 'بين', 'عبر',
]);

function computeTopWords(posts, limit = 15) {
  const counts = {};
  for (const p of posts) {
    const words = (p.text || '').split(/[\s،.,؛:!؟?()«»"'\-]+/).filter(Boolean);
    for (const w of words) {
      const clean = w.trim();
      if (clean.length < 3) continue;
      if (STOPWORDS.has(clean)) continue;
      counts[clean] = (counts[clean] || 0) + 1;
    }
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([word, count]) => ({ word, count }));
}

app.get('/api/wordcloud', requireTabAccess('wordcloud'), async (req, res) => {
  const raw = await redis.get('posts');
  const allPosts = raw ? JSON.parse(raw) : [];
  const now = Date.now();
  const todayStart = getDamascusDayStartMs(now);
  const todayPosts = allPosts.filter((p) => p.date >= todayStart && p.date <= now);
  const words = computeTopWords(todayPosts, 40);
  res.json({ words, newsCount: todayPosts.length });
});

/* ---------------------------------------------------------------------
   کمکی مشترک: فراخوانی DeepSeek با خروجی JSON
--------------------------------------------------------------------- */
function safeTruncate(str, maxLen) {
  if (!str) return '';
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}
function stripLoneSurrogates(str) {
  return str.replace(/[\uD800-\uDFFF]/g, '');
}

async function callDeepSeekJson(userPrompt, systemPrompt) {
  if (!DEEPSEEK_API_KEY) throw new Error('کلید DEEPSEEK_API_KEY تنظیم نشده است.');

  const res = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${DEEPSEEK_API_KEY}` },
    body: JSON.stringify({
      model: 'deepseek-chat',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.4,
    }),
  });

  const rawBody = await res.text();
  if (!res.ok) throw new Error(`دیپ‌سیک خطای ${res.status} برگرداند: ${rawBody.slice(0, 300)}`);

  let data;
  try { data = JSON.parse(rawBody); } catch { throw new Error('پاسخ دیپ‌سیک JSON معتبر نبود.'); }

  const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!content) throw new Error('پاسخ دیپ‌سیک ساختار مورد انتظار را نداشت.');

  const cleaned = stripLoneSurrogates(content.replace(/```json/g, '').replace(/```/g, '').trim());
  return JSON.parse(cleaned);
}

async function checkAiToolCooldown(cooldownKey) {
  const now = Date.now();
  const lastRaw = await redis.get(cooldownKey);
  const last = lastRaw ? parseInt(lastRaw, 10) : 0;
  if (now - last < AI_TOOL_COOLDOWN_MS) {
    return Math.ceil((AI_TOOL_COOLDOWN_MS - (now - last)) / 1000);
  }
  await redis.set(cooldownKey, String(now));
  return 0;
}

/* ---------------------------------------------------------------------
   گزارش عملیات روانی
--------------------------------------------------------------------- */
async function callDeepSeekReport(posts) {
  if (!DEEPSEEK_API_KEY || posts.length === 0) {
    return {
      summary: posts.length === 0 ? 'امروز هنوز خبری ثبت نشده است.' : 'کلید DeepSeek تنظیم نشده؛ فقط آمار خام موجود است.',
      techniques: [],
      importantNews: [],
      top5News: [],
    };
  }

  const joined = posts.slice(0, 60).map((p, i) => `${i + 1}. ${safeTruncate(p.text, 400)}`).join('\n');
  const prompt = `متن‌های خبری زیر مربوط به امروز هستند (احتمالاً به عربی). تحلیل زیر را انجام بده و فقط یک JSON خام برگردان:
{
  "summary": "خلاصه‌ی مدیریتی ۲ تا ۴ جمله‌ای به فارسی از مهم‌ترین روند امروز",
  "techniques": ["تکنیک‌های احتمالی عملیات روانی شناسایی‌شده، هرکدام یک رشته‌ی کوتاه فارسی"],
  "importantNews": ["مهم‌ترین رویدادهای امروز، هرکدام یک جمله‌ی کوتاه فارسی"],
  "top5News": ["۵ خبر برتر امروز به فارسی، خلاصه‌شده"]
}

اخبار امروز:
${joined}`;

  try {
    return await callDeepSeekJson(prompt, 'تو فقط خروجی JSON معتبر تولید می‌کنی، بدون هیچ متن اضافه.');
  } catch (e) {
    return { summary: 'خطا در تحلیل هوش مصنوعی: ' + e.message, techniques: [], importantNews: [], top5News: [] };
  }
}

app.get('/api/psyop-report', requireAnyTabAccess('psyop', 'infographic'), async (req, res) => {
  const raw = await redis.get('psyop_report_latest');
  res.json({ report: raw ? JSON.parse(raw) : null });
});

app.post('/api/psyop-report/generate', requireTabAccess('psyop'), async (req, res) => {
  const waitSec = await checkAiToolCooldown('psyop_last_call');
  if (waitSec > 0) return res.status(429).json({ ok: false, error: `لطفاً ${waitSec} ثانیه‌ی دیگر دوباره تلاش کن.` });

  const raw = await redis.get('posts');
  const allPosts = raw ? JSON.parse(raw) : [];
  const now = Date.now();
  const periodStart = getDamascusDayStartMs(now);
  const periodPosts = allPosts.filter((p) => p.date >= periodStart && p.date <= now);

  const topWords = computeTopWords(periodPosts);
  const ai = await callDeepSeekReport(periodPosts);

  const report = {
    generatedAt: now,
    periodStart,
    periodEnd: now,
    newsCount: periodPosts.length,
    topWords,
    summary: ai.summary,
    techniques: ai.techniques,
    importantNews: ai.importantNews,
    top5News: ai.top5News,
  };

  await redis.set('psyop_report_latest', JSON.stringify(report));

  const historyRaw = await redis.get('psyop_report_history');
  let history = historyRaw ? JSON.parse(historyRaw) : [];
  history.unshift({ generatedAt: now, newsCount: report.newsCount, summary: report.summary });
  history = history.slice(0, 30);
  await redis.set('psyop_report_history', JSON.stringify(history));

  res.json({ ok: true, report });
});

/* ---------------------------------------------------------------------
   سناریو ساز و کپشن ساز
--------------------------------------------------------------------- */
const SCENARIO_FORMAT_LABELS = {
  poster: 'پوستر (تصویر ثابت همراه با متن)',
  photo_caption: 'عکس‌نوشته (تصویر همراه با یک نقل‌قول یا متن کوتاه روی آن)',
  video: 'ویدیوی کوتاه (مثل ریلز/شورت)',
  documentary: 'مستند بلند',
};
const LANGUAGE_LABELS = { fa: 'فارسی', en: 'انگلیسی', ar: 'عربی', es: 'اسپانیایی', fr: 'فرانسوی' };
const ARABIC_DIALECT_LABELS = {
  iraqi: 'لهجه‌ی عراقی', levantine: 'لهجه‌ی شامی', gulf: 'لهجه‌ی شبه‌جزیره‌ای',
  egyptian: 'لهجه‌ی مصری', sudanese: 'لهجه‌ی سودانی',
};
const PLATFORM_LABELS = { twitter: 'ایکس (توییتر)', facebook: 'فیس‌بوک', instagram: 'اینستاگرام', telegram: 'تلگرام', youtube: 'یوتیوب' };

function resolveLanguageInstruction(language, arabicDialect) {
  if (language === 'ar') return `زبان عربی، به ${ARABIC_DIALECT_LABELS[arabicDialect] || 'عربی فصیح رسانه‌ای'}`;
  return LANGUAGE_LABELS[language] || LANGUAGE_LABELS.fa;
}
function clampCount(value) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return 1;
  return Math.min(Math.max(n, 1), 5);
}

app.post('/api/scenario/generate', requireTabAccess('scenario'), async (req, res) => {
  const waitSec = await checkAiToolCooldown('scenario_last_call');
  if (waitSec > 0) return res.status(429).json({ ok: false, error: `لطفاً ${waitSec} ثانیه‌ی دیگر دوباره تلاش کن.` });

  const text = (req.body.text || '').toString();
  if (!text.trim()) return res.status(400).json({ ok: false, error: 'متن خبر خالی است.' });

  const format = SCENARIO_FORMAT_LABELS[req.body.format] ? req.body.format : 'video';
  const language = LANGUAGE_LABELS[req.body.language] ? req.body.language : 'fa';
  const languageInstruction = resolveLanguageInstruction(language, req.body.arabicDialect);
  const count = clampCount(req.body.count);
  const instructions = (req.body.instructions || '').toString().trim();

  const formatGuide = {
    poster: 'هر نسخه شامل دقیقاً یک بخش («پوستر») باشد: تیتر کوتاه در text، توصیف ترکیب‌بندی بصری در visual. duration خالی بماند.',
    photo_caption: 'هر نسخه شامل یک یا دو بخش کوتاه («عکس‌نوشته») باشد: متن کوتاه در text، پیشنهاد تصویر در visual. duration خالی بماند.',
    video: 'هر نسخه شامل ۳ تا ۶ «شات» باشد؛ duration به ثانیه، متن گفتاری در text، پیشنهاد تصویر/ویدیو در visual.',
    documentary: 'هر نسخه شامل ۴ تا ۸ بخش باشد؛ duration به دقیقه، متن روایت در text، پیشنهاد فوتیج در visual.',
  };

  const prompt = `متن خبر زیر را در نظر بگیر. ${count} نسخه‌ی متفاوت سناریو برای تولید یک «${SCENARIO_FORMAT_LABELS[format]}» بساز.
زبان خروجی: ${languageInstruction}.
${formatGuide[format]}
${instructions ? `دستورالعمل اضافی که باید رعایت شود: «${instructions}»` : ''}

خروجی را فقط JSON خام بده:
{ "variants": [ { "title": "...", "overview": "...", "sections": [ { "label": "...", "duration": "...", "text": "...", "visual": "..." } ] } ] }
باید دقیقاً ${count} آیتم در variants باشد.

متن خبر:
${safeTruncate(text, 1500)}`;

  try {
    const scenario = await callDeepSeekJson(prompt, 'تو فقط خروجی JSON معتبر تولید می‌کنی، بدون هیچ متن اضافه.');
    res.json({ ok: true, scenario });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.post('/api/caption/generate', requireTabAccess('caption'), async (req, res) => {
  const waitSec = await checkAiToolCooldown('caption_last_call');
  if (waitSec > 0) return res.status(429).json({ ok: false, error: `لطفاً ${waitSec} ثانیه‌ی دیگر دوباره تلاش کن.` });

  const text = (req.body.text || '').toString();
  if (!text.trim()) return res.status(400).json({ ok: false, error: 'متن خبر خالی است.' });

  const language = LANGUAGE_LABELS[req.body.language] ? req.body.language : 'fa';
  const languageInstruction = resolveLanguageInstruction(language, req.body.arabicDialect);
  const count = clampCount(req.body.count);
  const instructions = (req.body.instructions || '').toString().trim();
  const requestedPlatforms = Array.isArray(req.body.platforms) ? req.body.platforms.filter((p) => PLATFORM_LABELS[p]) : [];
  const platforms = requestedPlatforms.length > 0 ? requestedPlatforms : ['instagram'];

  const platformGuide = {
    twitter: 'کوتاه و مستقیم، حداکثر ۲۸۰ کاراکتر، با ۲ تا ۳ هشتگ',
    facebook: 'توضیح کامل‌تر و روایی‌تر، مناسب تعامل بیشتر',
    instagram: 'جذاب و کمی احساسی، با ایموجی و چند هشتگ',
    telegram: 'خلاصه‌ی خبری مستقیم و رسمی',
    youtube: 'یک خط جذاب اول، سپس توضیح بیشتر و چند هشتگ',
  };
  const platformsList = platforms.map((p) => `- ${PLATFORM_LABELS[p]}: ${platformGuide[p]}`).join('\n');
  const jsonShapeExample = platforms.map((p) => `"${p}": ["...", "..."]`).join(', ');

  const prompt = `متن خبر زیر را در نظر بگیر. برای هرکدام از شبکه‌های زیر، دقیقاً ${count} نسخه‌ی کپشن بساز:
${platformsList}

زبان خروجی: ${languageInstruction}.
${instructions ? `دستورالعمل اضافی که باید رعایت شود: «${instructions}»` : ''}

خروجی را فقط JSON خام بده؛ برای هر پلتفرم یک آرایه‌ی دقیقاً ${count} عضوی:
{ ${jsonShapeExample} }

متن خبر:
${safeTruncate(text, 1500)}`;

  try {
    const captions = await callDeepSeekJson(prompt, 'تو فقط خروجی JSON معتبر تولید می‌کنی، بدون هیچ متن اضافه.');
    res.json({ ok: true, captions });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

/* ---------------------------------------------------------------------
   رصد یوتیوب (کلیدواژه‌ی سوریه)
   چون اتصال مستقیم از سرور ایرانی به یوتیوب فیلتره، از طریق واسط
   Cloudflare (همون Workerی که برای وبهوک تلگرام هم استفاده می‌شه) رد می‌شیم.

   منطق ذخیره‌سازی: ویدیوهای هر روز جدا و به‌صورت تجمیعی ذخیره می‌شن —
   یعنی هر بار که جست‌وجوی جدید انجام می‌شه، نتایج به ویدیوهای همون روز
   اضافه می‌شن (نه جایگزین)، و روز بعد از صفر (یه کلید جدید) شروع می‌شه.
   این‌جوری آرشیو کامل هر روز هم به‌صورت خودکار نگه داشته می‌شه.
--------------------------------------------------------------------- */
const YOUTUBE_FETCH_INTERVAL_MS = 2 * 60 * 60 * 1000; // هر ۲ ساعت یک‌بار واقعاً از یوتیوب می‌گیریم (صرفه‌جویی سهمیه)
const YOUTUBE_KEYWORD = 'سوريا أخبار';

app.get('/api/youtube-videos', requireTabAccess('youtube'), async (req, res) => {
  const now = Date.now();
  const today = toDamascusDateString(now);
  const dayKey = `youtube_videos:${today}`;
  const lastFetchKey = `youtube_last_fetch:${today}`;

  const dayRaw = await redis.get(dayKey);
  let dayData = dayRaw ? JSON.parse(dayRaw) : { videos: [], fetchedAt: null };

  const lastFetchRaw = await redis.get(lastFetchKey);
  const lastFetch = lastFetchRaw ? parseInt(lastFetchRaw, 10) : 0;
  const needsFetch = now - lastFetch >= YOUTUBE_FETCH_INTERVAL_MS;

  if (!needsFetch) {
    return res.json({ videos: dayData.videos, fetchedAt: dayData.fetchedAt });
  }
  if (!YOUTUBE_API_KEY) {
    return res.json({ videos: dayData.videos, fetchedAt: dayData.fetchedAt, error: 'کلید YOUTUBE_API_KEY تنظیم نشده.' });
  }
  if (!RELAY_URL || !RELAY_SECRET) {
    return res.json({ videos: dayData.videos, fetchedAt: dayData.fetchedAt, error: 'RELAY_URL یا RELAY_SECRET تنظیم نشده.' });
  }

  await redis.set(lastFetchKey, String(now));

  try {
    const proxyUrl = `${RELAY_URL}/youtube?secret=${encodeURIComponent(RELAY_SECRET)}&q=${encodeURIComponent(YOUTUBE_KEYWORD)}&key=${encodeURIComponent(YOUTUBE_API_KEY)}`;
    const apiRes = await fetch(proxyUrl);
    const rawBody = await apiRes.text();
    if (!apiRes.ok) throw new Error(`واسط یوتیوب خطای ${apiRes.status} برگرداند`);
    const data = JSON.parse(rawBody);

    const newVideos = (data.items || []).map((item) => {
      const snippet = item.snippet || {};
      const thumbs = snippet.thumbnails || {};
      return {
        videoId: item.id && item.id.videoId,
        title: snippet.title || '',
        channelTitle: snippet.channelTitle || '',
        publishedAt: snippet.publishedAt || null,
        thumbnail: (thumbs.medium || thumbs.default || {}).url || null,
      };
    }).filter((v) => v.videoId);

    // ادغام با ویدیوهای قبلیِ همین روز، بدون تکراری
    const merged = [...dayData.videos];
    for (const v of newVideos) {
      const idx = merged.findIndex((m) => m.videoId === v.videoId);
      if (idx >= 0) merged[idx] = v;
      else merged.unshift(v);
    }
    merged.sort((a, b) => new Date(b.publishedAt || 0) - new Date(a.publishedAt || 0));

    await redis.set(dayKey, JSON.stringify({ videos: merged, fetchedAt: now }));
    res.json({ videos: merged, fetchedAt: now });
  } catch (e) {
    res.json({ videos: dayData.videos, fetchedAt: dayData.fetchedAt, error: e.message });
  }
});

// آرشیو ویدیوهای یوتیوب یک روز خاص
app.get('/api/youtube-archive', requireTabAccess('youtube'), async (req, res) => {
  const dateParam = req.query.date;
  if (!dateParam) return res.json({ videos: [] });
  const raw = await redis.get(`youtube_videos:${dateParam}`);
  const data = raw ? JSON.parse(raw) : null;
  res.json({ videos: data ? data.videos : [] });
});

/* ---------------------------------------------------------------------
   نوار «خبر فوری» — کانال عمومی الجزیره، ترجمه‌شده به فارسی با دیپ‌سیک،
   از طریق واسط Cloudflare خونده می‌شه (چون t.me تو ایران فیلتره).
--------------------------------------------------------------------- */
const BREAKING_NEWS_CHANNEL = 'aljazeeraBrk';
const BREAKING_NEWS_CACHE_MS = 3 * 60 * 1000;
const MAX_BREAKING_NEWS = 8;

async function translateBatchToPersian(texts) {
  if (!DEEPSEEK_API_KEY) return texts;
  if (texts.length === 0) return [];

  const numbered = texts.map((t, i) => `${i + 1}. ${safeTruncate(t, 500)}`).join('\n');
  const prompt = `متن‌های زیر خبرهای عربی هستند. هرکدام را به فارسیِ روان و خبری ترجمه کن.
فقط یک آرایه‌ی JSON از رشته‌ها برگردان، دقیقاً به همان ترتیب و همان تعداد ورودی، بدون هیچ توضیح یا متن اضافه.

${numbered}`;

  try {
    const result = await callDeepSeekJson(prompt, 'تو فقط یک آرایه‌ی JSON از رشته‌های ترجمه‌شده برمی‌گردانی، بدون هیچ متن اضافه.');
    if (Array.isArray(result) && result.length === texts.length) return result;
    return texts;
  } catch {
    return texts;
  }
}

app.get('/api/breaking-news', requireAuth, async (req, res) => {
  const now = Date.now();
  const cacheKey = 'breaking_news_cache';
  const cachedRaw = await redis.get(cacheKey);
  let cached = cachedRaw ? JSON.parse(cachedRaw) : null;

  if (cached && now - cached.fetchedAt < BREAKING_NEWS_CACHE_MS) {
    return res.json({ items: cached.items });
  }

  try {
    const html = await fetchTelegramPreviewHtml(BREAKING_NEWS_CHANNEL);
    const raw = parseTelegramPreviewPosts(html).reverse().slice(0, MAX_BREAKING_NEWS);
    if (raw.length === 0) {
      if (cached) return res.json({ items: cached.items });
      return res.json({ items: [] });
    }

    const translations = await translateBatchToPersian(raw.map((p) => p.text));
    const items = raw.map((p, i) => ({ id: p.id, link: p.link, date: p.date, text: translations[i] || p.text }));

    await redis.set(cacheKey, JSON.stringify({ fetchedAt: now, items }));
    res.json({ items });
  } catch (e) {
    if (cached) return res.json({ items: cached.items, error: e.message });
    res.json({ items: [], error: e.message });
  }
});

/* ---------------------------------------------------------------------
   سرو فایل‌های استاتیک فرانت‌اند (خروجی build شده‌ی Vite) + SPA fallback
--------------------------------------------------------------------- */
const FRONTEND_DIST = path.join(__dirname, 'public');
app.use(express.static(FRONTEND_DIST));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(FRONTEND_DIST, 'index.html'));
});

/* ---------------------------------------------------------------------
   اجرا
--------------------------------------------------------------------- */
redis.connect().then(() => {
  app.listen(PORT, () => console.log(`اشراف روی پورت ${PORT} در حال اجراست`));
}).catch((err) => {
  console.error('اتصال به Redis ناموفق بود:', err);
  process.exit(1);
});
