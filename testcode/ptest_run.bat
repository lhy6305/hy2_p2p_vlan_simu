@echo off
title run-test
chcp 65001
cls

if not exist "ptest.exe" (
exit /b
)

ptest.exe

echo.
echo program exited with code %errorlevel%.
echo press any key to exit.
pause>nul

exit /b
