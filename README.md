# 🔍 URL Threat Analyzer

أداة تحليل أمان URLs بواجهة Django.

## المميزات
- 🔬 **Static Analysis** — فحص HTTPS، IP، كلمات مشبوهة
- 🕵️ **WHOIS Lookup** — عمر الدومين، المالك، تاريخ الانتهاء
- 🌐 **DNS Resolution** — تحويل الدومين لـ IP
- 🛡️ **VirusTotal** — فحص بأكثر من 70 محرك
- 🧪 **urlscan.io** — Sandbox كامل مع screenshot

---

## التثبيت

### 1. تثبيت المتطلبات
```bash
pip install -r requirements.txt
```

### 2. إعداد API Keys
انسخ ملف `.env` وضع مفاتيحك:
```
VT_API_KEY=مفتاحك_من_virustotal.com
URLSCAN_API_KEY=مفتاحك_من_urlscan.io
```

> ⚠️ ملف `.env` مذكور في `.gitignore` — **لن يُرفع على GitHub أبداً**

### 3. تشغيل السيرفر
```bash
python manage.py runserver
```
ثم افتح: **http://127.0.0.1:8000**

---

## النشر على Railway

1. ارفع الكود على GitHub
2. اذهب لـ [railway.app](https://railway.app) وربط الـ repo
3. في **Variables** أضف:
   ```
   VT_API_KEY=مفتاحك
   URLSCAN_API_KEY=مفتاحك
   ```
4. Railway سيشغّل `Procfile` تلقائياً

---

## هيكل المشروع
```
url_analyzer/
├── .env              ← مفاتيح API (لا تُرفع على GitHub)
├── .gitignore
├── Procfile          ← للنشر على Railway
├── requirements.txt
├── manage.py
├── url_analyzer/     ← إعدادات Django
├── analyzer/         ← منطق التحليل
├── templates/
└── static/
```
