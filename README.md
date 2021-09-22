# react-native-blind-threshold-bls

## Description

This is a React Native wrapper for the [Celo Threshold BLS Rust library](https://github.com/celo-org/celo-threshold-bls-rs)

It works on iOS and Android, providing access to the crypto operations implemented by the rust library.

## Getting started

`$ npm install react-native-blind-threshold-bls --save`

## Usage

```javascript
import BlindThresholdBls from 'react-native-blind-threshold-bls';

BlindThresholdBls;
```

## Updating the libs

The precompiled libs for android (`.so` files) and ios (`.a` file) and checked into this repo.
To update them, follow the instructions in the celo-threshold-bls-rs repo to create the libs and then copy them over here.

Android libs live in `android/src/main/jniLibs`.
The combined iOS lib lives in `ios/Libraries`.

Additionally, the header file for the FFI bindings must be included here to support compilation for iOS.
That file is located at `ios/Headers/threshold.h`. Do not modify that file directly. If the FFI interface must change, change it in the celo-threshold-bls-rs repo and copy the header file here.

## Proguard

To accomodate JNA, add the following to the consuming app's proguard rules:

```
-dontwarn java.awt.*
-keep class com.sun.jna.* { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
```

## Building

### Android

To build the Android library, you can use the `gradlew` script.

```shell
cd android
chmod u+x gradlew
./gradlew assembleDebug
```
