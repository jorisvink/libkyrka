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
    -output Clibkyrka.xcframework

cat >> Clibkyrka.xcframework/ios-arm64/Headers/libkyrka/module.modulemap << _EOF
module Clibkyrka {
       header "libkyrka.h"
       header "libkyrka-kdf.h"
       export *
}
_EOF

cp Clibkyrka.xcframework/ios-arm64/Headers/libkyrka/module.modulemap \
   Clibkyrka.xcframework/ios-arm64-simulator/Headers/libkyrka/module.modulemap
