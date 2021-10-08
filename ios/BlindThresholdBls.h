#import <React/RCTBridgeModule.h>

@interface BlindThresholdBls : NSObject <RCTBridgeModule>

+ (uint8_t*) nsDataToByteArray: (NSData*)data;
- (void) blindMessage: (NSString *) message
                 randomness:(NSString *) randomness
                 resolver:(RCTPromiseResolveBlock) resolve
                 rejecter:(RCTPromiseRejectBlock) reject;

@end
