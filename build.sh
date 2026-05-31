#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

cd "$SCRIPT_DIR"

~/flutter/bin/flutter build apk --release

cp build/app/outputs/flutter-apk/app-release.apk "$SCRIPT_DIR/app-release.apk"

echo "APK ready: $SCRIPT_DIR/app-release.apk"
