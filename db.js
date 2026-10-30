/**
 * ==============================================================================
 * طبقة قاعدة البيانات المشتركة - جمعية الهلال الأحمر السوداني (فرع الولاية الشمالية)
 * تدعم الاتصال المزدوج:
 * 1. PostgreSQL لقواعد البيانات السحابية الحقيقية (Supabase, Railway, Neon, VPS)
 * 2. SQLite المحلية المدمجة الدائمة كـ Fallback فوري وفعّال
 * ==============================================================================
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');

let isPg = false;
let pgPool = null;
let sqliteDb = null;

const dbUrl = process.env.DATABASE_URL;

if (dbUrl && (dbUrl.startsWith('postgres://') || dbUrl.startsWith('postgresql://'))) {
  isPg = true;
  pgPool = new Pool({
    connectionString: dbUrl,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  console.log('✅ تم تهيئة الاتصال بقاعدة بيانات PostgreSQL السحابية.');
} else {
  isPg = false;
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  const dbFile = path.join(dataDir, 'srcs_northern_state.db');
  sqliteDb = new sqlite3.Database(dbFile, (err) => {
    if (err) {
      console.error('❌ خطأ في فتح قاعدة بيانات SQLite:', err.message);
    } else {
      console.log(`✅ تم تفعيل قاعدة البيانات المحلية المشتركة والدائمة: ${dbFile}`);
    }
  });
}

// تنفيذ استعلام متعدد البارامترات بصيغة موحدة
async function query(sql, params = []) {
  if (isPg) {
    // تحويل علامات ? إلى $1, $2, ... في PostgreSQL
    let pIdx = 1;
    const pgSql = sql.replace(/\?/g, () => `$${pIdx++}`);
    const res = await pgPool.query(pgSql, params);
    return { rows: res.rows, rowCount: res.rowCount };
  } else {
    return new Promise((resolve, reject) => {
      const trimmed = sql.trim().toUpperCase();
      if (trimmed.startsWith('SELECT') || trimmed.startsWith('PRAGMA')) {
        sqliteDb.all(sql, params, (err, rows) => {
          if (err) return reject(err);
          resolve({ rows: rows || [], rowCount: (rows || []).length });
        });
      } else {
        sqliteDb.run(sql, params, function (err) {
          if (err) return reject(err);
          resolve({ rows: [], rowCount: this.changes, lastID: this.lastID });
        });
      }
    });
  }
}

// تهيئة الجداول وبناء الهيكل الأساسي للبيانات
async function initDatabase() {
  console.log('🔄 جاري التحقق من جداول المنظومة وتحديث المخطط الهيكلي...');

  // 1. جدول المشرفين والإدارة
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'مشرف محتوى',
      branch TEXT NOT NULL DEFAULT 'كافة المحليات',
      status TEXT NOT NULL DEFAULT 'نشط',
      permissions TEXT NOT NULL DEFAULT '["posts","comments"]',
      two_factor_secret TEXT,
      two_factor_enabled INTEGER DEFAULT 0,
      last_login TEXT,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    )
  `);

  // 2. جدول الأخبار والتقارير الميدانية
  await query(`
    CREATE TABLE IF NOT EXISTS posts (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      title TEXT NOT NULL,
      title_en TEXT,
      branch TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'relief',
      category_label TEXT NOT NULL DEFAULT 'إغاثة وطوارئ',
      date TEXT NOT NULL,
      image TEXT,
      video TEXT,
      summary TEXT,
      summary_en TEXT,
      content TEXT NOT NULL,
      content_en TEXT,
      views INTEGER DEFAULT 0,
      likes INTEGER DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'منشور',
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    )
  `);

  // 3. جدول صندوق الشكاوى والبلاغات والمقترحات
  await query(`
    CREATE TABLE IF NOT EXISTS suggestions (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      tracking_number TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL,
      branch TEXT NOT NULL,
      sender_name TEXT NOT NULL DEFAULT 'مواطن',
      sender_phone TEXT,
      subject TEXT NOT NULL,
      content TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'جديد',
      official_response TEXT,
      response_by TEXT,
      response_at TEXT,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    )
  `);

  // 4. جدول التعليقات والتفاعل
  await query(`
    CREATE TABLE IF NOT EXISTS comments (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      post_id INTEGER NOT NULL,
      author TEXT NOT NULL,
      author_email TEXT,
      avatar TEXT,
      text TEXT NOT NULL,
      likes INTEGER DEFAULT 0,
      is_approved INTEGER DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    )
  `);

  // 5. جدول مستخدمي الموقع الموثقين عبر Google
  await query(`
    CREATE TABLE IF NOT EXISTS citizens (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      google_id TEXT UNIQUE,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      avatar TEXT,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
      last_seen TEXT
    )
  `);

  // 6. جدول إحصائيات وإعدادات المنصة (CMS)
  await query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  // 7. جدول سجل التدقيق الأمني (Audit Logs)
  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id ${isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT'},
      event TEXT NOT NULL,
      username TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    )
  `);

  console.log('✅ تم اكتمال بناء وتأكيد جداول قاعدة البيانات بنجاح.');
}

module.exports = {
  query,
  initDatabase,
  isPg: () => isPg
};
