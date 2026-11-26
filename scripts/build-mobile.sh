#!/usr/bin/env bash
set -euo pipefail

# Cross-platform mobile packaging script for Nexus-IO (`profile-android` & `profile-ios`)
# - Android: builds arm64-v8a / x86_64 `.so` libraries via `cargo-ndk` for Android System WebView apps
# - iOS: builds W^X-compliant `aarch64-apple-ios` staticlib + `XCFramework` for WKWebView Swift apps

TARGET="${1:-all}"

if [[ "$TARGET" == "android" || "$TARGET" == "all" ]]; then
  echo "🤖 Building Nexus-IO for Android (profile-android,gui)..."
  cargo ndk -t arm64-v8a -t x86_64 -o ./dist/android/jniLibs \
    build --release --lib --no-default-features --features profile-android,gui
  echo "✅ Android libraries written to ./dist/android/jniLibs"
fi

if [[ "$TARGET" == "ios" || "$TARGET" == "all" ]]; then
  echo "🍎 Building Nexus-IO for iOS (profile-ios,gui — W^X runtime-only Wasm)..."
  cargo build --release --lib --target aarch64-apple-ios --no-default-features --features profile-ios,gui
  cargo build --release --lib --target aarch64-apple-ios-sim --no-default-features --features profile-ios,gui
  if command -v xcodebuild >/dev/null 2>&1; then
    rm -rf ./dist/ios/NexusIO.xcframework
    xcodebuild -create-xcframework \
      -library target/aarch64-apple-ios/release/libnexus_io.a -headers include \
      -library target/aarch64-apple-ios-sim/release/libnexus_io.a -headers include \
      -output ./dist/ios/NexusIO.xcframework
    echo "✅ iOS XCFramework written to ./dist/ios/NexusIO.xcframework"
  fi
fi
