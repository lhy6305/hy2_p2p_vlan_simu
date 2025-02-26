@echo off
go fmt .
if not %errorlevel% == 0 (
echo.
echo program exited with code %errorlevel%.
echo press any key to exit.
pause>nul
)