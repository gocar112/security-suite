@echo off
python "%~dp0security_suite.py" launch
if errorlevel 1 pause
