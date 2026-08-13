@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo             p2p_12 - Inicializacao
echo ========================================
echo.
if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Criando ambiente virtual Python 3.14...
    py -3.14 -m venv .venv
    if errorlevel 1 (
        echo ERRO: Python 3.14 nao foi encontrado ou a virtualenv falhou.
        pause
        exit /b 1
    )
) else echo [1/3] Ambiente virtual ja existe.
echo.
echo [2/3] Verificando dependencias...
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERRO: Falha ao instalar dependencias.
    pause
    exit /b 1
)
echo.
echo [3/3] Iniciando p2p_12...
echo.
set "APP_FILE=p2p_12.py"
if not exist "%APP_FILE%" (
    echo ERRO: Arquivo principal nao encontrado: %APP_FILE%
    pause
    exit /b 1
)
.venv\Scripts\python.exe "%APP_FILE%" %*
if errorlevel 1 (
    echo.
    echo p2p_12 foi encerrado com erro. Codigo: %errorlevel%
    pause
    exit /b %errorlevel%
)
endlocal
