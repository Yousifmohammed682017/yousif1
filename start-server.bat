@echo off
chcp 65001 >nul
title SRCS Northern State - Full Platform Server

echo.
echo ==============================================================
echo  جمعية الهلال الأحمر السوداني - فرع الولاية الشمالية
echo  تشغيل الخادم المتكامل وقاعدة البيانات المشتركة
echo ==============================================================
echo.

node -v >nul 2>&1
if errorlevel 1 (
    echo [!] Node.js غير مثبت في هذا الجهاز. يرجى تثبيته من nodejs.org
    pause
    exit
)

echo [+] جاري تشغيل الخادم المركزي على المنفذ 5000...
echo.
echo [+] يمكنك الوصول للصفحات على:
echo     الموقع العام للمواطنين : http://localhost:5000
echo     لوحة تحكم الإدارة     : http://localhost:5000/admin.html
echo     متابعة الشكاوى        : http://localhost:5000/track-complaint.html
echo.
echo [!] لا تغلق هذه النافذة أثناء العمل. اضغط Ctrl+C لإيقاف الخادم.
echo.

start "" "http://localhost:5000"

node server.js
