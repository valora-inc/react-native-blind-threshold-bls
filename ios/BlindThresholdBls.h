#import <React/RCTBridgeModule.h>

@interface BlindThresholdBls : NSObject <RCTBridgeModule>

+ (uint8_t*) nsDataToByteArray: (NSData*)data;

@end
