@echo off
echo ========================================================
echo   GARANTILI EXE OLUSTURMA ARACI
echo ========================================================
echo.

echo 1. Python kontrol ediliyor...
python --version
IF %ERRORLEVEL% NEQ 0 (
    echo HATA: Python yuklu degil veya PATH'e ekli degil!
    pause
    exit
)

echo.
echo 2. Gerekli paketler YUKLENIYOR (Zorunlu)...
python -m pip install --upgrade pip
python -m pip install flask flask-sqlalchemy flask-wtf flask-talisman flask-limiter pandas openpyxl pyinstaller flask-login

echo.
echo 3. EXE Olusturuluyor (PyInstaller)...
:: python -m PyInstaller kullanıyoruz çünkü path sorunu olmasın
:: Spec dosyasi varsa onu kullan, yoksa parametrelerle olustur
IF EXIST "KutuphaneSistemi.spec" (
    echo Spec dosyasi bulundu, kullaniliyor...
    python -m PyInstaller KutuphaneSistemi.spec --clean --noconfirm
) ELSE (
    echo Spec dosyasi bulunamadi, parametrelerle olusturuluyor...
    python -m PyInstaller --noconsole --onefile --clean --noconfirm --name "KutuphaneSistemi" --add-data "templates;templates" --add-data "static;static" --hidden-import "pandas" --hidden-import "openpyxl" --hidden-import "sqlalchemy.sql.default_comparator" app.py
)

echo.
echo ========================================================
echo   ISLEM TAMAMLANDI!
echo ========================================================
echo.
echo Olusturulan dosya: dist/KutuphaneSistemi.exe
pause
