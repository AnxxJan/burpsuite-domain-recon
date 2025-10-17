@echo off
REM Build script for BurpSuite Domain Reconnaissance Extension (Windows)

echo ================================================
echo   BurpSuite Domain Reconnaissance Extension
echo   Build Script (Windows)
echo ================================================
echo.

REM Check if Maven is installed
where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo X Maven is not installed or not in PATH
    echo Please install Maven: https://maven.apache.org/install.html
    exit /b 1
)

REM Check if Java is installed
where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo X Java is not installed or not in PATH
    echo Please install Java JDK 11+: https://adoptium.net/
    exit /b 1
)

echo OK Maven found
mvn -version | findstr "Apache Maven"
echo OK Java found
java -version 2>&1 | findstr "version"
echo.

REM Clean previous builds
echo Cleaning previous builds...
call mvn clean
if %ERRORLEVEL% NEQ 0 (
    echo X Clean failed
    exit /b 1
)
echo.

REM Compile and package
echo Compiling and packaging...
call mvn package
if %ERRORLEVEL% NEQ 0 (
    echo X Build failed
    exit /b 1
)
echo.

REM Check if JAR was created
if exist "target\domain-recon-1.0.0.jar" (
    echo OK Build successful!
    echo.
    echo Extension JAR created at:
    echo    target\domain-recon-1.0.0.jar
    echo.
    for %%I in (target\domain-recon-1.0.0.jar) do echo File size: %%~zI bytes
    echo.
    echo Next steps:
    echo    1. Open BurpSuite
    echo    2. Go to Extender - Extensions
    echo    3. Click Add - Select Java
    echo    4. Choose target\domain-recon-1.0.0.jar
    echo    5. Click Next
    echo.
) else (
    echo X JAR file was not created
    exit /b 1
)

echo ================================================
echo   Build Complete!
echo ================================================
pause
