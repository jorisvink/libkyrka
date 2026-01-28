#!/bin/sh
#
# Build all ios targets and bundle them in libkyrka.xcframework

set -e

./dist-build/ios-arm64-build.sh
./dist-build/ios-simulator-arm64-build.sh

xcodebuild -create-xcframework \
    -library ios-arm64/lib/libkyrka.a \
    -headers ios-arm64/include/ \
    -library ios-simulator-arm64/lib/libkyrka.a \
    -headers ios-simulator-arm64/include/ \
    -output libkyrka.xcframework
