@echo off
setlocal enablelayedexpansion

:: Set the env variable
set "LD_PRELOAD=C:\Users\User\Desktop\Computer stuff\Tor clone\toralize.dll"

:: Run the provided command with its args
"%*"

:: Unset env variables
set "LD_PRELOAD="

endlocal