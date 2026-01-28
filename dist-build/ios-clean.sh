#!/bin/sh
#
# Remove all ios builds

./dist-build/ios-arm64-clean.sh
./dist-build/ios-simulator-arm64-clean.sh

rm -rf libkyrka.xcframework
