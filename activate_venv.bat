@echo off
echo Activating Maxelo Work Management Virtual Environment...
echo.

REM Check if venv exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Virtual Environment activated successfully!
echo You can now run: python app.py
echo.
pause