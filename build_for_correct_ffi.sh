# Set deployment target to match your app
export MACOSX_DEPLOYMENT_TARGET=15.0

# Clean and rebuild
cargo clean
cargo build --release --target aarch64-apple-darwin

# Replace the library
cp target/aarch64-apple-darwin/release/libxaeroid.a ~/XaeroIDWallet/XaeroIDWallet/lib/libxaeroid_macos.a

# Verify the new library's deployment target
otool -l ~/XaeroIDWallet/XaeroIDWallet/lib/libxaeroid_macos.a | grep -A 3 LC_VERSION_MIN_MACOSX
