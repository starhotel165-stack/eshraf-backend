/**
 * اسکریپت ساخت کاربر مدیر کل (اجرا فقط رو خودِ سرور، مستقیم از خط فرمان)
 * این فقط برای ساخت اولین حساب مدیره؛ کاربرهای عادی بعداً از پنل مدیریت
 * کاربران (تو خودِ سایت) با دسترسی محدود به تب‌های دلخواه ساخته می‌شن.
 *
 * استفاده: node create-user.js <username> <password>
 */
const crypto = require('crypto');
const { createClient } = require('redis');

const ALL_TAB_KEYS = ['live', 'wordcloud', 'youtube', 'archive', 'psyop', 'infographic', 'scenario', 'caption'];

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({ hash: derivedKey.toString('hex'), salt: salt.toString('hex') });
    });
  });
}

async function main() {
  const [username, password] = process.argv.slice(2);
  if (!username || !password) {
    console.error('استفاده: node create-user.js <username> <password>');
    process.exit(1);
  }
  if (password.length < 8) {
    console.error('رمز عبور باید حداقل ۸ کاراکتر باشد.');
    process.exit(1);
  }

  const redis = createClient({ url: process.env.REDIS_URL || 'redis://127.0.0.1:6379' });
  await redis.connect();

  const existing = await redis.get(`user:${username}`);
  if (existing) {
    console.error(`کاربر «${username}» از قبل وجود دارد. برای تغییر رمز، اول با redis-cli حذفش کن: DEL user:${username}`);
    process.exit(1);
  }

  const { hash, salt } = await hashPassword(password);
  await redis.set(`user:${username}`, JSON.stringify({ username, hash, salt, role: 'admin', allowedTabs: ALL_TAB_KEYS }));
  console.log(`کاربر «${username}» با دسترسی مدیر کل ساخته شد.`);

  await redis.quit();
}

main();
