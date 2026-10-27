@echo off
cd /d "%~dp0docker_security_tool"
echo Dang khoi dong Web Dashboard...
start "" "http://127.0.0.1:8888"
python app_web.py
