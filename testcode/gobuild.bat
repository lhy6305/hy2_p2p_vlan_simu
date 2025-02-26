@echo off

del /f ptest.exe 1>nul 2>nul

set GOOS=windows
set GOARCH=amd64
go build -v -o ptest.exe -ldflags "-s -w -buildid=" -trimpath .
if not %errorlevel% == 0 (
echo.
echo program exited with code %errorlevel%.
echo press any key to exit.
pause>nul
)
