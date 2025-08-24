#!/bin/bash
set -e

export IPHONEOS_DEPLOYMENT_TARGET=13.0

echo "Building for iOS 13.0..."

cargo rustc --release --target aarch64-apple-ios -- \
    -C link-arg=-target -C link-arg=aarch64-apple-ios13.0

cargo rustc --release --target aarch64-apple-ios-sim -- \
    -C link-arg=-target -C link-arg=aarch64-apple-ios13.0-simulator

cargo rustc --release --target x86_64-apple-ios -- \
    -C link-arg=-target -C link-arg=x86_64-apple-ios13.0-simulator

# Create universal simulator library
lipo -create \
    target/x86_64-apple-ios/release/libxaeroid.a \
    target/aarch64-apple-ios-sim/release/libxaeroid.a \
    -output target/libxaeroid-sim.a

echo "✅ Done!"