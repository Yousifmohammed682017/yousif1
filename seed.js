/**
 * ==============================================================================
 * بذر وتهيئة البيانات الرسمية الأولية في قاعدة البيانات المشتركة
 * ==============================================================================
 */

const bcrypt = require('bcryptjs');
const db = require('./db');

async function seedInitialData() {
  // 1. التحقق من وجود المستخدمين
  const usersRes = await db.query('SELECT COUNT(*) as count FROM users');
  const userCount = parseInt(usersRes.rows[0].count || usersRes.rows[0].COUNT || 0);

  if (userCount === 0) {
    console.log('🌱 جاري إضافة حسابات المشرفين الرسمية بقاعدة البيانات مع تشفير كلمات المرور...');
    
    // تشفير كلمات المرور الافتراضية
    const hashedAdminPin = await bcrypt.hash('2026', 10);
    const hashDn = await bcrypt.hash('dnq2026', 10);
    const hashMrw = await bcrypt.hash('mrw2026', 10);
    const hashDlq = await bcrypt.hash('dlq2026', 10);
    const hashBrq = await bcrypt.hash('brq2026', 10);
    const hashAbh = await bcrypt.hash('abh2026', 10);

    const initialUsers = [
      {
        name: 'أحمد الفاتح البدوي',
        username: 'admin.director',
        email: 'admin@srcs.sd',
        password_hash: hashedAdminPin,
        role: 'مدير عام',
        branch: 'كافة المحليات',
        status: 'نشط',
        permissions: JSON.stringify(['all'])
      },
      {
        name: 'سيف الدين خضر',
        username: 'saif.khedir',
        email: 's.khedir@srcs.sd',
        password_hash: hashDn,
        role: 'مشرف محتوى',
        branch: 'محلية دنقلا',
        status: 'نشط',
        permissions: JSON.stringify(['posts', 'comments'])
      },
      {
        name: 'فاطمة الزبير',
        username: 'fatima.zubair',
        email: 'f.elzubair@srcs.sd',
        password_hash: hashMrw,
        role: 'مشرف تفاعل',
        branch: 'محلية مروي والدبة',
        status: 'نشط',
        permissions: JSON.stringify(['complaints', 'comments'])
      },
      {
        name: 'عثمان إدريس دلقو',
        username: 'othman.idris',
        email: 'o.idris@srcs.sd',
        password_hash: hashDlq,
        role: 'مشرف تفاعل',
        branch: 'محلية دلقو',
        status: 'نشط',
        permissions: JSON.stringify(['complaints', 'comments'])
      },
      {
        name: 'طه محمد البرقيق',
        username: 'taha.burgaig',
        email: 't.burgaig@srcs.sd',
        password_hash: hashBrq,
        role: 'مشرف محتوى',
        branch: 'محلية البرقيق',
        status: 'نشط',
        permissions: JSON.stringify(['posts', 'comments'])
      },
      {
        name: 'نادية إبراهيم',
        username: 'nadia.ibrahim',
        email: 'n.ibrahim@srcs.sd',
        password_hash: hashAbh,
        role: 'مشرف تفاعل',
        branch: 'محلية ابو حمد',
        status: 'موقوف',
        permissions: JSON.stringify(['complaints', 'comments'])
      }
    ];

    for (const u of initialUsers) {
      await db.query(
        `INSERT INTO users (name, username, email, password_hash, role, branch, status, permissions)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [u.name, u.username, u.email, u.password_hash, u.role, u.branch, u.status, u.permissions]
      );
    }
    console.log('✅ تم تسجيل وتأمين حسابات المشرفين بنجاح.');
  }

  // 2. التحقق من وجود الأخبار والتقارير
  const postsRes = await db.query('SELECT COUNT(*) as count FROM posts');
  const postCount = parseInt(postsRes.rows[0].count || postsRes.rows[0].COUNT || 0);

  if (postCount === 0) {
    console.log('🌱 جاري إضافة التقارير والأخبار الميدانية الأولية بقاعدة البيانات...');
    
    const initialPosts = [
      {
        title: 'استجابة طوارئ الهلال الأحمر بالولاية الشمالية: قوافل إغاثية متكاملة لـ 2,400 أسرة متضررة بقرى دنقلا ومروي',
        title_en: 'SRCS Northern State Emergency Response: Integrated Relief Convoys for 2,400 Affected Families in Dongola and Merowe',
        branch: 'دنقلا',
        category: 'relief',
        category_label: 'إغاثة وطوارئ',
        date: '25 أكتوبر 2026',
        image: 'https://images.unsplash.com/photo-1488521787991-ed7bbaae773c?auto=format&fit=crop&w=1200&q=80',
        video: '',
        summary: 'سيّرت غرفة الطوارئ المركزية بفرع جمعية الهلال الأحمر السوداني بالولاية الشمالية قافلة مساعدات عاجلة تشمل مواد إيوائية وطرود غذائية.',
        summary_en: 'The Emergency Operations Center of SRCS Northern State dispatched urgent relief convoys including shelter materials and food parcels.',
        content: `في إطار التدخلات الميدانية الإنسانية المستمرة لفرع جمعية الهلال الأحمر السوداني بالولاية الشمالية، تم تسيير قوافل إغاثية متكاملة شملت توزيع 1,200 خيمة إيوائية و4,800 طرد غذائي و200,000 حبة كلور لتنقية مياه الشرب. وشاركت الفرق التطوعية في عمليات الإخلاء والإسعاف الأولي وتوزيع الدعم النفسي والاجتماعي.`,
        content_en: `Within the ongoing humanitarian field interventions of the Sudanese Red Crescent Society Northern State Branch, integrated relief convoys were dispatched covering the distribution of 1,200 shelter tents, 4,800 food kits, and 200,000 water purification tablets. Volunteer teams actively engaged in evacuations, first aid, and psychosocial support.`,
        views: 2380,
        likes: 142,
        status: 'منشور'
      },
      {
        title: 'تأهيل وتجهيز مراكز العزل الميداني ودعم غرف طوارئ الكوليرا وحمى الضنك بمستشفى مروي التعليمي',
        title_en: 'Rehabilitation and Equipping of Field Isolation Centers Supporting Cholera and Dengue Emergency Wards at Merowe Hospital',
        branch: 'مروي',
        category: 'health',
        category_label: 'رعاية صحية',
        date: '24 أكتوبر 2026',
        image: 'https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?auto=format&fit=crop&w=1200&q=80',
        video: '',
        summary: 'نفذت إدارة الصحة والرعاية المجتمعية تدخلاً طبياً مكثفاً لتعزيز قدرة غرف الطوارئ الصحية وتوفير أدوية الطوارئ والمحاليل الوريدية.',
        summary_en: 'The Department of Health and Community Care implemented an intensive medical intervention boosting emergency healthcare capacities.',
        content: `استجابةً للوضع الوبائي، نفذت إدارة الصحة والرعاية المجتمعية تدخلاً طبياً مكثفاً شمل تزويد مستشفى مروي التعليمي ومراكز الدبة الصحية بأكثر من 3,500 زجاجة محلول وريدي، وتدريب 85 متطوعاً ومتطوعة على بروتوكولات مكافحة العدوى والتقصي الوبائي المبكر.`,
        content_en: `Responding to epidemiological conditions, the Health and Community Care Department delivered over 3,500 IV fluid units to Merowe Teaching Hospital and Eldaba health centers, and trained 85 volunteers on infection control and early surveillance protocols.`,
        views: 1845,
        likes: 98,
        status: 'منشور'
      },
      {
        title: 'برنامج الإصحاح البيئي الشامل: حملات رش الضباب وتطهير الآبار ومحطات المياه بمحلية الدبة',
        title_en: 'Comprehensive Environmental Sanitation Program: Fog Spraying and Water Well Chlorination Campaigns in Eldaba Locality',
        branch: 'الدبة',
        category: 'wash',
        category_label: 'إصحاح بيئي',
        date: '23 أكتوبر 2026',
        image: 'https://images.unsplash.com/photo-1542601906990-b4d3fb778b09?auto=format&fit=crop&w=1200&q=80',
        video: '',
        summary: 'اختتام المرحلة الأولى من حملة التطهير البيئي ومكافحة نواقل الأمراض بالتنسيق مع وزارة الصحة الولائية.',
        summary_en: 'Conclusion of Phase One environmental disinfection and disease vector control campaign coordinated with the State Ministry of Health.',
        content: `شهدت محلية الدبة ومناطق الغابة والدفار اختتام المرحلة الأولى من حملة الإصحاح البيئي الشاملة، حيث تم تطهير وتعقيم 14 محطة مياه نيلية و62 بئراً جوفية، بالإضافة إلى رش 4,800 منزل بمبيدات مكافحة نواقل الأمراض ونواقل الملاريا.`,
        content_en: `Eldaba locality and surrounding areas concluded Phase One of the comprehensive environmental sanitation campaign, disinfecting 14 river water stations and 62 boreholes, as well as spraying 4,800 residences against disease vectors.`,
        views: 1420,
        likes: 85,
        status: 'منشور'
      },
      {
        title: 'تخريج 120 مسعفاً ومسعفة من شباب محليتي دلقو والبرقيق ضمن برنامج الإسعاف الميداني المجتمعي',
        title_en: 'Graduation of 120 Community First Responders from Delgo and Al-Borgaig Youth under First Aid Program',
        branch: 'دلقو',
        category: 'firstaid',
        category_label: 'إسعاف أولي',
        date: '21 أكتوبر 2026',
        image: 'https://images.unsplash.com/photo-1584515979956-d9f6e5d09982?auto=format&fit=crop&w=1200&q=80',
        video: '',
        summary: 'احتفلت إدارة التدريب وتنمية التطوع بتخريج دفعة جديدة من فرق الطوارئ الأهلية الجاهزة للتدخل السريع.',
        summary_en: 'The Training and Volunteer Development Department celebrated the graduation of a new batch of community emergency responders.',
        content: `ضمن خطة بناء القدرات المجتمعية لمواجهة الأزمات، تم تخريج 120 متطوعاً ومتطوعة تم تدريبهم مكثفاً على مهارات إنعاش القلب والرئتين، إيقاف النزيف، تضميد الجروح الميدانية، وإدارة الإخلاء الطبي أثناء الكوارث الطبيعية.`,
        content_en: `Under the community capacity-building plan for crisis preparedness, 120 young volunteers graduated following intensive training in CPR, bleeding control, trauma dressing, and medical evacuation management during emergencies.`,
        views: 1190,
        likes: 114,
        status: 'منشور'
      }
    ];

    for (const p of initialPosts) {
      await db.query(
        `INSERT INTO posts (title, title_en, branch, category, category_label, date, image, video, summary, summary_en, content, content_en, views, likes, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [p.title, p.title_en, p.branch, p.category, p.category_label, p.date, p.image, p.video, p.summary, p.summary_en, p.content, p.content_en, p.views, p.likes, p.status]
      );
    }
    console.log('✅ تم تسجيل الأخبار والتقارير الميدانية الأولية بنجاح.');
  }

  // 3. التحقق من الشكاوى الأولية
  const sugRes = await db.query('SELECT COUNT(*) as count FROM suggestions');
  const sugCount = parseInt(sugRes.rows[0].count || sugRes.rows[0].COUNT || 0);

  if (sugCount === 0) {
    const initialSuggestions = [
      {
        tracking_number: 'SUG-8821',
        type: 'شكوى عاجلة',
        branch: 'دنقلا',
        sender_name: 'أحمد الطيب البدري',
        sender_phone: '0912345678',
        subject: 'انقطاع إمداد مياه الشرب بمربع 5 بعد السيول',
        content: 'نرجو توجيه فريق الإصحاح البيئي لمعاينة بئر المياه الرئيسية بعد تلوثها بالسيول الأخيرة لضمان سلامة الأهالي.',
        status: 'قيد المعالجة',
        official_response: 'تم توجيه فريق طوارئ المياه والإصحاح البيئي بمحلية دنقلا للموقع وسيتم سحب العينات وتطهير البئر خلال 24 ساعة.',
        response_by: 'أحمد الفاتح البدوي (المدير العام)'
      },
      {
        tracking_number: 'SUG-8822',
        type: 'طلب مساعدة',
        branch: 'مروي',
        sender_name: 'مواطن',
        sender_phone: '',
        subject: 'طلب طرود إيوائية لأسر نازحة في مركز إيواء كريمة',
        content: 'هناك 40 أسرة وافدة تحتاج لأغطية ومشمعات ومواد إيواء طارئة.',
        status: 'مكتمل',
        official_response: 'تم تسليم 45 طرد إيواء متكامل وإرسال عيادة ميدانية متنقلة للأسر بالمركز بالتعاون مع محلية مروي.',
        response_by: 'فاطمة الزبير (مشرف تفاعل)'
      }
    ];

    for (const s of initialSuggestions) {
      await db.query(
        `INSERT INTO suggestions (tracking_number, type, branch, sender_name, sender_phone, subject, content, status, official_response, response_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [s.tracking_number, s.type, s.branch, s.sender_name, s.sender_phone, s.subject, s.content, s.status, s.official_response, s.response_by]
      );
    }
  }

  // 4. التحقق من الإعدادات العامة للمنصة
  const settingsRes = await db.query("SELECT value FROM settings WHERE key = 'site_cms_data'");
  if (settingsRes.rows.length === 0) {
    const defaultCms = {
      ticker: [
        'غرفة طوارئ الهلال الأحمر بالولاية الشمالية تعمل على مدار 24 ساعة لمتابعة الأوضاع الإنسانية',
        'بدء توزيع 4,800 سلة غذائية للأسر المتضررة بمحليات دنقلا ومروي والدبة بدعم من الشركاء الدوليين',
        'إطلاق حملة التطعيم الوقائي والإصحاح البيئي الشامل بكافة محليات الولاية الشمالية السبع',
        'الخط الساخن المركزي لطوارئ الهلال الأحمر بالولاية الشمالية: 02481-22450 متاح لاستقبال البلاغات'
      ],
      stats: {
        localitiesCount: 7,
        beneficiaries: 184500,
        coveragePct: 94,
        volunteers: 3420,
        foodKits: 14200,
        waterChlorine: 2800000
      },
      contacts: {
        centralPhone: '02481-22450',
        emergencyHotline: '0123-456789',
        officialEmail: 'info@srcs-northern.sd'
      }
    };

    await db.query("INSERT INTO settings (key, value) VALUES ('site_cms_data', ?)", [JSON.stringify(defaultCms)]);
  }

  console.log('✅ تم الانتهاء من فحص وتأكيد جاهزية كافة البيانات المشتركة.');
}

module.exports = { seedInitialData };
