@echo off
echo Activating virtual environment...
call venv\Scripts\activate

echo Installing requirements...
pip install -r requirements.txt

echo Starting Flask application...
start python app.py
start http://127.0.0.1:5000