@echo off
del .\\idm-bypass.exe

cargo build --release
move .\\target\\release\\idm-bypass.exe .\\idm-bypass.exe
pause