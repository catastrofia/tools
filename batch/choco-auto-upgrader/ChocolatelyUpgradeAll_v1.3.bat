::=============================================
::   ChocoAutoUpdate V1.3 - August 2023
::=============================================
::
::=============================================
:: Automatically checks Chocolately installed
:: packages and performs necesarry updates.
::=============================================

@echo off

setlocal

:: setESC is for color formatting, taken from the win10colors.cmd script by mlocati
:: link: https://gist.github.com/mlocati/fdabcaeb8071d5c75a2d51712db24011#file-win10colors-cmd

call :setESC

::This is the current version of the script
set version=v1.3

title Chocolately AutoUpdater %version%

:://///////////Introduction///////////////////
::Prints script version and asks the user whether they want to check and update now or not

echo %ESC%[7;94m================================================%ESC%[0m
echo %ESC%[7;94m                                                %ESC%[0m               
echo %ESC%[7;94m    "This is Chocolately AutoUpdater %version%"      %ESC%[0m
echo %ESC%[7;94m                                                %ESC%[0m
echo %ESC%[7;94m================================================%ESC%[0m
echo:
echo "I'm here to keep your programs up to date, but first ..."
echo:
echo:

::////////////Ask the user and get the answer//////////////
:: If the answer does not start with either "y" or "Y" the program goes to section "othertime"

:PROMPT
SET /P AREYOUSURE=%ESC%[7mDo you want to check your programs and update now ([y]/[n])?%ESC%[0m
IF /I "%AREYOUSURE:~0,1%" NEQ "y" IF /I "%AREYOUSURE:~0,1%" NEQ "Y" GOTO :othertime

:://///////////Case of the user answering yes///////////////
:: Proceeds with calling chocolately upgrade all command

echo:
echo %ESC%[7m"Ok, I'll check what needs to be updated."%ESC$%
echo:
call choco upgrade all -y

:: Chocolately ran succesfully meaning errorlevel = 0 then goes to "next"

if %ERRORLEVEL% == 0 goto :next
if %ERRORLEVEL% == -1 goto :admin
:: If any errors were encountered the program prints the errors and goes to endofscript
echo "Errors encountered during execution.  Exited with status: %errorlevel%"
goto :endofscript

:: Tells the user that the program ran succesfully

:next
echo:
echo:
echo %ESC%[7;92m=================================================================%ESC$%
echo %ESC%[7;92m          "Smile :). Your programs are now up to date."          %ESC$%
echo %ESC%[7;92m=================================================================%ESC$%
echo:
GOTO END

::////////// Case the user types anything that does not start with "y" or "Y"//////////////

:othertime
echo:
echo:
echo:
echo %ESC%[7;93m=================================================================%ESC$% 
echo %ESC%[7;93m            "All good, I'll check back tomorrow"                 %ESC$%
echo %ESC%[7;93m=================================================================%ESC$%
echo:
goto END

:admin
echo %ESC%[7;91m"Upps, chocolately requires you to run this program as an administrator."%ESC%[0m
echo:
echo %ESC%[7;91m"Close this instance and run the script again as an administrator"%ESC%[0m
echo:
goto END

:endofscript
echo %ESC%[91m"The program encountered some errors."%ESC%[0m
goto END

:setESC
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set ESC=%%b
  exit /B 0
)

:END
pause
endlocal
