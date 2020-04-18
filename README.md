# react-native-blind-threshold-bls

## Getting started

`$ npm install react-native-blind-threshold-bls --save`

## Usage

```javascript
import BlindThresholdBls from 'react-native-blind-threshold-bls';

BlindThresholdBls;
```

## Proguard

To accomodate JNA, add the following to the consuming app's proguard rules:

```
-dontwarn java.awt.*
-keep class com.sun.jna.* { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
```