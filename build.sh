#!/bin/bash

# Build script for BurpSuite Domain Reconnaissance Extension

echo "================================================"
echo "  BurpSuite Domain Reconnaissance Extension"
echo "  Build Script"
echo "================================================"
echo ""

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven is not installed or not in PATH"
    echo "Please install Maven: https://maven.apache.org/install.html"
    exit 1
fi

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "❌ Java is not installed or not in PATH"
    echo "Please install Java JDK 11+: https://adoptium.net/"
    exit 1
fi

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F '.' '{print $1}')
if [ "$JAVA_VERSION" -lt 11 ]; then
    echo "❌ Java version 11 or higher is required"
    echo "Current version: $(java -version 2>&1 | head -n 1)"
    exit 1
fi

echo "✅ Maven found: $(mvn -version | head -n 1)"
echo "✅ Java found: $(java -version 2>&1 | head -n 1)"
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
mvn clean
if [ $? -ne 0 ]; then
    echo "❌ Clean failed"
    exit 1
fi
echo ""

# Compile and package
echo "🔨 Compiling and packaging..."
mvn package
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo ""

# Check if JAR was created
if [ -f "target/domain-recon-1.0.0.jar" ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📦 Extension JAR created at:"
    echo "   target/domain-recon-1.0.0.jar"
    echo ""
    echo "📋 File size: $(du -h target/domain-recon-1.0.0.jar | cut -f1)"
    echo ""
    echo "🚀 Next steps:"
    echo "   1. Open BurpSuite"
    echo "   2. Go to Extender → Extensions"
    echo "   3. Click Add → Select Java"
    echo "   4. Choose target/domain-recon-1.0.0.jar"
    echo "   5. Click Next"
    echo ""
else
    echo "❌ JAR file was not created"
    exit 1
fi

echo "================================================"
echo "  Build Complete!"
echo "================================================"
