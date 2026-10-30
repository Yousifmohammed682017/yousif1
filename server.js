/**
 * ==============================================================================
 * الخادم الخلفي المتكامل وواجهات الـ RESTful API
 * جمعية الهلال الأحمر السوداني - فرع الولاية الشمالية
 * ==============================================================================
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const path = require('path');
const otplib = require('otplib');
const qrcode = require('qrcode');

const db = require('./db');
const { seedInitialData } = require('./seed');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'srcs_secret_jwt_northern_state_2026';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';

// تهيئة Google OAuth Client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// 1. إجراءات الحماية والأمان للخادم (Security Middlewares)
app.use(helmet({
  contentSecurityPolicy: false, // للسماح بتحميل مكتبات CDN مثل Tailwind و Chart.js و FontAwesome
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// حماية ضد الهجمات المتكررة (Rate Limiting)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 300, // حد أقصى 300 طلب لكل IP
  message: { success: false, message: 'تم تجاوز الحد المسموح به من الطلبات مؤقتاً، يرجى المحاولة لاحقاً.' }
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20, // 20 محاولة تسجيل دخول كحد أقصى لكل 10 دقائق
  message: { success: false, message: 'تم تجاوز الحد الأقصى لمحاولات تسجيل الدخول، يرجى الانتظار 10 دقائق.' }
});

// خدمة الملفات الثابتة للموقع
app.use(express.static(path.join(__dirname)));

// 2. دوال المصادقة والتحقق من الصلاحيات (Authentication & RBAC Middlewares)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'يجب تسجيل الدخول أولاً للوصول إلى هذا المورد.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'جلسة العمل غير صالحة أو انتهت مدتها، يرجى تسجيل الدخول مجدداً.' });
    }
    req.user = user;
    next();
  });
}

// التحقق من صلاحية المدير العام حصراً
function requireSuperAdmin(req, res, next) {
  if (req.user && req.user.role === 'مدير عام') {
    next();
  } else {
    return res.status(403).json({ success: false, message: 'عذراً! هذه العملية مقتصرة حصرياً على المدير العام.' });
  }
}

// التحقق من الصلاحيات المخصصة
function requirePermission(perm) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, message: 'غير مصرح.' });
    if (req.user.role === 'مدير عام') return next();

    const permissions = req.user.permissions || [];
    if (permissions.includes('all') || permissions.includes(perm)) {
      return next();
    }
    return res.status(403).json({ success: false, message: `عذراً! لا تملك صلاحية (${perm}) لإتمام هذه العملية.` });
  };
}

// ==============================================================================
// 3. واجهات المصادقة والإشراف (Auth & User Management APIs)
// ==============================================================================

// أ) تسجيل دخول المدير العام أو المشرف
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password, totpToken } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'يرجى إدخال اسم المستخدم وكلمة المرور.' });
    }

    const trimmedUser = username.trim().toLowerCase();
    const result = await db.query('SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?', [trimmedUser, trimmedUser]);

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة.' });
    }

    const user = result.rows[0];

    if (user.status !== 'نشط') {
      return res.status(403).json({ success: false, message: 'هذا الحساب معلق حالياً. يرجى مراجعة إدارة الفرع.' });
    }

    // التحقق من كلمة المرور المشفرة
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة.' });
    }

    // التحقق من 2FA إذا كان مفعلاً
    if (user.two_factor_enabled === 1 && user.two_factor_secret) {
      if (!totpToken) {
        return res.json({
          success: true,
          requires2FA: true,
          message: 'يرجى إدخال رمز التحقق الثنائي (2FA).'
        });
      }
      const isValidTotp = otplib.authenticator.check(totpToken, user.two_factor_secret);
      if (!isValidTotp) {
        return res.status(401).json({ success: false, message: 'رمز التحقق الثنائي (2FA) غير صحيح.' });
      }
    }

    let perms = [];
    try { perms = typeof user.permissions === 'string' ? JSON.parse(user.permissions) : user.permissions; } catch (e) { perms = []; }

    // إصدار رمز JWT آمن
    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        branch: user.branch,
        permissions: perms
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    // تحديث آخر تسجيل دخول وسجل التدقيق
    const nowStr = new Date().toLocaleString('ar-SD');
    await db.query('UPDATE users SET last_login = ? WHERE id = ?', [nowStr, user.id]);
    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[AUTH] تسجيل دخول ناجح (${user.role})`,
      user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        branch: user.branch,
        permissions: perms,
        twoFactorEnabled: user.two_factor_enabled === 1
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في معالجة طلب تسجيل الدخول.' });
  }
});

// ب) تفعيل وتجهيز رمز 2FA (QR Code) للمدير أو المشرف
app.post('/api/auth/2fa/setup', authenticateToken, async (req, res) => {
  try {
    const secret = otplib.authenticator.generateSecret();
    const otpauth = otplib.authenticator.keyuri(req.user.email, 'SRCS Northern State', secret);
    const qrCodeUrl = await qrcode.toDataURL(otpauth);

    res.json({
      success: true,
      secret,
      qrCodeUrl
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر إنشاء رمز التحقق الثنائي.' });
  }
});

// ج) تأكيد تفعيل 2FA
app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
  try {
    const { secret, token } = req.body;
    const isValid = otplib.authenticator.check(token, secret);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'رمز التحقق غير صحيح، تأكد من الوقت في هاتفك.' });
    }

    await db.query('UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?', [secret, req.user.id]);
    res.json({ success: true, message: 'تم تفعيل التحقق الثنائي بنجاح لحسابك.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تفعيل التحقق الثنائي.' });
  }
});

// د) واجهات إدارة المشرفين (مقتصرة على المدير العام فقط)
app.get('/api/users', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT id, name, username, email, role, branch, status, permissions, last_login, created_at FROM users ORDER BY id ASC');
    const users = result.rows.map(u => ({
      ...u,
      permissions: typeof u.permissions === 'string' ? JSON.parse(u.permissions || '[]') : u.permissions
    }));
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تحميل قائمة المشرفين.' });
  }
});

app.post('/api/users', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { name, username, email, password, role, branch, permissions } = req.body;
    if (!name || !username || !email || !password) {
      return res.status(400).json({ success: false, message: 'جميع الحقول الأساسية مطلوبة.' });
    }

    const checkExist = await db.query('SELECT id FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?', [username.toLowerCase().trim(), email.toLowerCase().trim()]);
    if (checkExist.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم أو البريد الإلكتروني مسجل بالفعل.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const permsJson = JSON.stringify(permissions || ['posts', 'comments']);

    await db.query(
      `INSERT INTO users (name, username, email, password_hash, role, branch, status, permissions)
       VALUES (?, ?, ?, ?, ?, ?, 'نشط', ?)`,
      [name.trim(), username.toLowerCase().trim(), email.toLowerCase().trim(), passwordHash, role || 'مشرف محتوى', branch || 'كافة المحليات', permsJson]
    );

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[USER] إضافة مشرف جديد (${name} - ${username})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم إنشاء حساب المشرف بنجاح.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل إنشاء حساب المشرف.' });
  }
});

app.put('/api/users/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, username, email, password, role, branch, status, permissions } = req.body;

    const exist = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (exist.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'المشرف غير موجود.' });
    }

    let passwordHash = exist.rows[0].password_hash;
    if (password && password.trim().length >= 4) {
      passwordHash = await bcrypt.hash(password.trim(), 10);
    }

    const permsJson = JSON.stringify(permissions || (exist.rows[0].permissions ? JSON.parse(exist.rows[0].permissions) : ['posts', 'comments']));

    await db.query(
      `UPDATE users SET name = ?, username = ?, email = ?, password_hash = ?, role = ?, branch = ?, status = ?, permissions = ?
       WHERE id = ?`,
      [name || exist.rows[0].name, (username || exist.rows[0].username).toLowerCase().trim(), (email || exist.rows[0].email).toLowerCase().trim(), passwordHash, role || exist.rows[0].role, branch || exist.rows[0].branch, status || exist.rows[0].status, permsJson, userId]
    );

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[USER] تعديل بيانات المشرف (${username || exist.rows[0].username})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم تحديث بيانات المشرف بنجاح.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر تعديل بيانات المشرف.' });
  }
});

// ==============================================================================
// 4. توثيق وتسجيل دخول المواطنين بواسطة Google OAuth 2.0 (الخطوة 4)
// ==============================================================================
app.post('/api/auth/google', async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ success: false, message: 'رمز الدخول الخاص بـ Google مفقود.' });
    }

    let payload = null;

    if (GOOGLE_CLIENT_ID) {
      // تحقق رسمي من توكن Google عبر المكتبة الرسمية
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: GOOGLE_CLIENT_ID
      });
      payload = ticket.getPayload();
    } else {
      // وضع التطوير إذا لم يتم توفير CLIENT_ID بعد
      const decoded = jwt.decode(idToken);
      if (decoded && decoded.email) {
        payload = decoded;
      } else {
        return res.status(400).json({ success: false, message: 'رمز Google غير صالح.' });
      }
    }

    const { sub: googleId, email, name, picture } = payload;

    // حفظ المواطن أو تحديث بياناته بقاعدة البيانات
    const existCitizen = await db.query('SELECT * FROM citizens WHERE email = ?', [email.toLowerCase()]);
    let citizen = null;
    const nowTime = new Date().toLocaleString('ar-SD');

    if (existCitizen.rows.length > 0) {
      await db.query('UPDATE citizens SET name = ?, avatar = ?, last_seen = ? WHERE email = ?', [name, picture, nowTime, email.toLowerCase()]);
      citizen = { ...existCitizen.rows[0], name, avatar: picture };
    } else {
      const ins = await db.query(
        'INSERT INTO citizens (google_id, name, email, avatar, last_seen) VALUES (?, ?, ?, ?, ?)',
        [googleId, name, email.toLowerCase(), picture, nowTime]
      );
      citizen = { id: ins.lastID, googleId, name, email, avatar: picture };
    }

    // إصدار توكن خاص بالمواطن (منفصل تماماً عن صلاحيات الإدارة)
    const citizenToken = jwt.sign(
      { id: citizen.id, name: citizen.name, email: citizen.email, avatar: citizen.avatar, type: 'citizen' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token: citizenToken,
      user: {
        id: citizen.id,
        name: citizen.name,
        email: citizen.email,
        avatar: citizen.avatar
      }
    });
  } catch (err) {
    console.error('Google Auth error:', err);
    res.status(500).json({ success: false, message: 'تعذر التحقق من حساب Google.' });
  }
});

// ==============================================================================
// 5. واجهات الأخبار والتقارير الميدانية والمحتوى (الخطوة 2 و 6)
// ==============================================================================

// جلب الأخبار لجميع الزوار (عام)
app.get('/api/posts', async (req, res) => {
  try {
    const { branch, category, search } = req.query;
    let sql = 'SELECT * FROM posts WHERE status = ?';
    let params = ['منشور'];

    if (branch && branch !== 'all') {
      sql += ' AND branch = ?';
      params.push(branch);
    }
    if (category && category !== 'all') {
      sql += ' AND category = ?';
      params.push(category);
    }
    if (search && search.trim()) {
      sql += ' AND (title LIKE ? OR summary LIKE ? OR content LIKE ?)';
      const term = `%${search.trim()}%`;
      params.push(term, term, term);
    }

    sql += ' ORDER BY id DESC';
    const result = await db.query(sql, params);
    res.json({ success: true, posts: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تحميل الأخبار.' });
  }
});

// جلب كافة الأخبار بما فيها المسودات للمشرفين في لوحة التحكم
app.get('/api/admin/posts', authenticateToken, requirePermission('posts'), async (req, res) => {
  try {
    let sql = 'SELECT * FROM posts';
    let params = [];

    // إذا كان المشرف مسؤولاً عن محلية محددة
    if (req.user.branch && req.user.branch !== 'كافة المحليات') {
      sql += ' WHERE branch = ? OR branch = ?';
      params.push(req.user.branch, req.user.branch.replace('محلية ', ''));
    }

    sql += ' ORDER BY id DESC';
    const result = await db.query(sql, params);
    res.json({ success: true, posts: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تحميل منشورات الإدارة.' });
  }
});

// جلب تفاصيل خبر محدد + زيادة المشاهدات
app.get('/api/posts/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'التقرير غير موجود.' });
    }
    // زيادة عدد المشاهدات
    await db.query('UPDATE posts SET views = views + 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true, post: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر جلب تفاصيل الخبر.' });
  }
});

// إضافة خبر جديد (محفوظ في قاعدة البيانات ليظهر فوراً للجميع)
app.post('/api/posts', authenticateToken, requirePermission('posts'), async (req, res) => {
  try {
    const { title, title_en, branch, category, category_label, date, image, video, summary, summary_en, content, content_en, status } = req.body;

    if (!title || !content) {
      return res.status(400).json({ success: false, message: 'عنوان الخبر وتفاصيله مطلوبة.' });
    }

    const postDate = date || new Date().toLocaleDateString('ar-SD', { year: 'numeric', month: 'long', day: 'numeric' });
    const postStatus = status || 'منشور';

    const ins = await db.query(
      `INSERT INTO posts (title, title_en, branch, category, category_label, date, image, video, summary, summary_en, content, content_en, views, likes, status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
      [title.trim(), title_en || '', branch || 'الولاية الشمالية', category || 'relief', category_label || 'إغاثة وطوارئ', postDate, image || '', video || '', summary || '', summary_en || '', content.trim(), content_en || '', postStatus, req.user.id]
    );

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[CONTENT] نشر خبر جديد (${title.substring(0, 40)}...)`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم نشر الخبر بنجاح في قاعدة البيانات المشتركة.', postId: ins.lastID });
  } catch (err) {
    console.error('Post creation error:', err);
    res.status(500).json({ success: false, message: 'فشل نشر الخبر.' });
  }
});

// تعديل خبر
app.put('/api/posts/:id', authenticateToken, requirePermission('posts'), async (req, res) => {
  try {
    const postId = req.params.id;
    const { title, title_en, branch, category, category_label, image, video, summary, summary_en, content, content_en, status } = req.body;

    await db.query(
      `UPDATE posts SET title = ?, title_en = ?, branch = ?, category = ?, category_label = ?, image = ?, video = ?, summary = ?, summary_en = ?, content = ?, content_en = ?, status = ?
       WHERE id = ?`,
      [title, title_en || '', branch, category, category_label, image, video, summary, summary_en, content, content_en, status || 'منشور', postId]
    );

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[CONTENT] تعديل الخبر رقم (${postId})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم حفظ التعديلات بنجاح.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تعديل الخبر.' });
  }
});

// حذف خبر
app.delete('/api/posts/:id', authenticateToken, requirePermission('posts'), async (req, res) => {
  try {
    const postId = req.params.id;
    await db.query('DELETE FROM posts WHERE id = ?', [postId]);
    await db.query('DELETE FROM comments WHERE post_id = ?', [postId]);

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[CONTENT] حذف الخبر رقم (${postId})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم حذف الخبر بنجاح من قاعدة البيانات.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل حذف الخبر.' });
  }
});

// تسجيل إعجاب بخبر
app.post('/api/posts/:id/like', async (req, res) => {
  try {
    await db.query('UPDATE posts SET likes = likes + 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// ==============================================================================
// 6. واجهات صندوق الشكاوى والبلاغات والمقترحات (الخطوة 5)
// ==============================================================================

// إرسال شكوى أو بلاغ أو مقترح جديد (متاح لجميع المواطنين)
app.post('/api/suggestions', async (req, res) => {
  try {
    const { type, branch, sender_name, sender_phone, subject, content, isAnon } = req.body;

    if (!subject || !content) {
      return res.status(400).json({ success: false, message: 'يرجى كتابة موضوع الشكوى وتفاصيلها.' });
    }

    // توليد رقم متابعة فريد ومميز
    const randomCode = Math.floor(1000 + Math.random() * 9000);
    const trackingNumber = `SRCS-${Date.now().toString().slice(-4)}-${randomCode}`;

    const displayName = isAnon ? 'فاعل خير (مجهول)' : (sender_name || 'مواطن');
    const displayPhone = isAnon ? '' : (sender_phone || '');

    await db.query(
      `INSERT INTO suggestions (tracking_number, type, branch, sender_name, sender_phone, subject, content, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'جديد')`,
      [trackingNumber, type || 'بلاغ عاجل', branch || 'دنقلا', displayName, displayPhone, subject.trim(), content.trim()]
    );

    res.json({
      success: true,
      message: 'تم استلام طلبك وحفظه بنجاح في قاعدة البيانات المركزية لفرع الولاية الشمالية.',
      trackingNumber
    });
  } catch (err) {
    console.error('Suggestion submission error:', err);
    res.status(500).json({ success: false, message: 'تعذر إرسال الشكوى، يرجى المحاولة لاحقاً.' });
  }
});

// استعلام المواطن عن حالة شكواه برقم المتابعة (آمن ولا يكشف بيانات غيره)
app.get('/api/suggestions/track/:trackingNumber', async (req, res) => {
  try {
    const tracking = req.params.trackingNumber.trim().toUpperCase();
    const result = await db.query(
      'SELECT tracking_number, type, branch, subject, status, official_response, response_by, response_at, created_at FROM suggestions WHERE UPPER(tracking_number) = ?',
      [tracking]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'رقم المتابعة غير موجود. يرجى التأكد من الرقم والمحاولة مجدداً.' });
    }

    res.json({
      success: true,
      complaint: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء الاستعلام.' });
  }
});

// استعراض الشكاوى للمشرفين في لوحة التحكم
app.get('/api/admin/suggestions', authenticateToken, requirePermission('complaints'), async (req, res) => {
  try {
    let sql = 'SELECT * FROM suggestions';
    let params = [];

    if (req.user.branch && req.user.branch !== 'كافة المحليات') {
      sql += ' WHERE branch = ? OR branch = ?';
      params.push(req.user.branch, req.user.branch.replace('محلية ', ''));
    }

    sql += ' ORDER BY id DESC';
    const result = await db.query(sql, params);
    res.json({ success: true, suggestions: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل استرجاع قائمة الشكاوى.' });
  }
});

// تحديث حالة الشكوى والرد عليها من المشرف
app.put('/api/admin/suggestions/:id/respond', authenticateToken, requirePermission('complaints'), async (req, res) => {
  try {
    const sugId = req.params.id;
    const { status, official_response } = req.body;
    const nowTime = new Date().toLocaleString('ar-SD');

    await db.query(
      `UPDATE suggestions SET status = ?, official_response = ?, response_by = ?, response_at = ?
       WHERE id = ?`,
      [status || 'تمت المراجعة', official_response || '', `${req.user.name} (${req.user.role})`, nowTime, sugId]
    );

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[COMPLAINTS] الرد على البلاغ رقم (${sugId}) وتحديث حالته إلى (${status})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم حفظ الرد وتحديث حالة البلاغ بنجاح.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تحديث حالة الشكوى.' });
  }
});

// ==============================================================================
// 7. واجهات التعليقات والرقابة عليها (الخطوة 7)
// ==============================================================================

// جلب التعليقات المعتمدة لخبر محدد
app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, post_id, author, avatar, text, likes, created_at FROM comments WHERE post_id = ? AND is_approved = 1 ORDER BY id DESC',
      [req.params.id]
    );
    res.json({ success: true, comments: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل تحميل التعليقات.' });
  }
});

// إضافة تعليق جديد (مع فلترة النصوص الخبيثة والألفاظ المسيئة)
app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const postId = req.params.id;
    const { author, author_email, avatar, text } = req.body;

    if (!text || text.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'لا يمكن إرسال تعليق فارغ.' });
    }

    // فلترة بسيطة للكلمات غير اللائقة
    const blockedWords = ['شتيمة', 'قذف', 'احتيال', 'نصب'];
    const lowerText = text.toLowerCase();
    const hasBadWord = blockedWords.some(w => lowerText.includes(w));

    // تنظيف النص ضد وسوم XSS
    const sanitizedText = text.replace(/</g, '&lt;').replace(/>/g, '&gt;').trim();
    const isApproved = hasBadWord ? 0 : 1;

    const ins = await db.query(
      `INSERT INTO comments (post_id, author, author_email, avatar, text, likes, is_approved)
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [postId, author ? author.trim() : 'مواطن', author_email || '', avatar || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=100&q=80', sanitizedText, isApproved]
    );

    res.json({
      success: true,
      message: isApproved ? 'تم نشر تعليقك بنجاح.' : 'تم استلام تعليقك وسيظهر بعد مراجعته من المشرفين.',
      comment: {
        id: ins.lastID,
        post_id: postId,
        author: author || 'مواطن',
        avatar: avatar || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=100&q=80',
        text: sanitizedText,
        likes: 0
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل إرسال التعليق.' });
  }
});

// استعراض وحذف التعليقات من لوحة التحكم
app.get('/api/admin/comments', authenticateToken, requirePermission('comments'), async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM comments ORDER BY id DESC');
    res.json({ success: true, comments: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل استرجاع التعليقات.' });
  }
});

app.delete('/api/admin/comments/:id', authenticateToken, requirePermission('comments'), async (req, res) => {
  try {
    await db.query('DELETE FROM comments WHERE id = ?', [req.params.id]);
    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[MODERATION] حذف التعليق رقم (${req.params.id})`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);
    res.json({ success: true, message: 'تم حذف التعليق بنجاح.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل حذف التعليق.' });
  }
});

// ==============================================================================
// 8. واجهات الإحصائيات الحقيقية وإعدادات الـ CMS (الخطوة 6 و 9)
// ==============================================================================

// جلب الإحصائيات الحقيقية المجمعة من قاعدة البيانات
app.get('/api/stats', async (req, res) => {
  try {
    const postsCount = await db.query('SELECT COUNT(*) as count FROM posts WHERE status = ?', ['منشور']);
    const suggestionsCount = await db.query('SELECT COUNT(*) as count FROM suggestions');
    const commentsCount = await db.query('SELECT COUNT(*) as count FROM comments WHERE is_approved = 1');
    const citizensCount = await db.query('SELECT COUNT(*) as count FROM citizens');

    const cmsRow = await db.query("SELECT value FROM settings WHERE key = 'site_cms_data'");
    let cmsData = {};
    if (cmsRow.rows.length > 0) {
      try { cmsData = JSON.parse(cmsRow.rows[0].value); } catch (e) {}
    }

    res.json({
      success: true,
      stats: {
        totalReports: parseInt(postsCount.rows[0].count || postsCount.rows[0].COUNT || 0),
        totalSuggestions: parseInt(suggestionsCount.rows[0].count || suggestionsCount.rows[0].COUNT || 0),
        totalComments: parseInt(commentsCount.rows[0].count || commentsCount.rows[0].COUNT || 0),
        registeredCitizens: parseInt(citizensCount.rows[0].count || citizensCount.rows[0].COUNT || 0),
        cmsStats: cmsData.stats || {},
        ticker: cmsData.ticker || [],
        contacts: cmsData.contacts || {}
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل جلب الإحصائيات.' });
  }
});

// تحديث بيانات CMS من لوحة التحكم (المدير العام)
app.put('/api/admin/cms', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { ticker, stats, contacts } = req.body;
    const cmsPayload = JSON.stringify({ ticker, stats, contacts });

    const check = await db.query("SELECT key FROM settings WHERE key = 'site_cms_data'");
    if (check.rows.length > 0) {
      await db.query("UPDATE settings SET value = ? WHERE key = 'site_cms_data'", [cmsPayload]);
    } else {
      await db.query("INSERT INTO settings (key, value) VALUES ('site_cms_data', ?)", [cmsPayload]);
    }

    await db.query('INSERT INTO audit_logs (event, username, ip) VALUES (?, ?, ?)', [
      `[CMS] تحديث إحصائيات وشريط الأخبار العاجلة للموقع`,
      req.user.username,
      req.ip || '127.0.0.1'
    ]);

    res.json({ success: true, message: 'تم حفظ إعدادات وإحصائيات الموقع بنجاح في قاعدة البيانات.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل حفظ إعدادات CMS.' });
  }
});

// سجل التدقيق الأمني (Audit Logs) للمدير العام فقط
app.get('/api/admin/audit-logs', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50');
    res.json({ success: true, logs: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'فشل استرجاع سجل التدقيق.' });
  }
});

// فحص جاهزية الخادم (Health Check)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    platform: 'SRCS Northern State Official Platform',
    database: db.isPg() ? 'PostgreSQL' : 'SQLite (Local Shared & Persistent)',
    time: new Date().toISOString()
  });
});

// توجيه أي رابط غير معروف إلى صفحة 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// تشغيل الخادم وتهيئة الجداول
async function startServer() {
  try {
    await db.initDatabase();
    await seedInitialData();

    app.listen(PORT, () => {
      console.log(`\n======================================================`);
      console.log(`🚀 خادم منصة الهلال الأحمر السوداني - الولاية الشمالية`);
      console.log(`🌐 يعمل بنجاح على الرابط: http://localhost:${PORT}`);
      console.log(`🗄️  قاعدة البيانات: ${db.isPg() ? 'PostgreSQL السحابية' : 'SQLite المحلية المشتركة الدائمة'}`);
      console.log(`======================================================\n`);
    });
  } catch (error) {
    console.error('❌ خطأ فادح في بدء تشغيل الخادم:', error);
    process.exit(1);
  }
}

startServer();
