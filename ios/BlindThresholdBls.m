#import "BlindThresholdBls.h"
#import "Headers/threshold.h"
#import <React/RCTLog.h>
#import <Foundation/Foundation.h>
#import <stdlib.h>
#import <stdint.h>

@implementation BlindThresholdBls {
  Token_PrivateKey* blindingFactor;
  Buffer messageBuf;
}

RCT_EXPORT_MODULE()

RCT_REMAP_METHOD(blindMessage,
                 message:(NSString *) message
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    RCTLogInfo(@"Preparing blind message buffers");
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    messageBuf.ptr = (uint8_t*)[messageData bytes];
    messageBuf.len = [messageData length];
//    uint8_t * messageBytes = malloc(length);
//    memcpy(messageBytes, [messageData bytes], length);
    Buffer blindedMessageBuf;
    
    RCTLogInfo(@"Preparing blinding seed");
    NSMutableData* seedData = [NSMutableData dataWithCapacity:32];
    for( unsigned int i = 0 ; i < 8; ++i )
    { 
      u_int32_t randomBits = arc4random();
      [seedData appendBytes:(void*)&randomBits length:4];
    }
    uint8_t *seedBytes = (uint8_t*)[seedData bytes];
    Buffer seedBuf;
    seedBuf.ptr = seedBytes;
    seedBuf.len = 32;

    RCTLogInfo(@"Calling blind");
    blind(&messageBuf, &seedBuf, &blindedMessageBuf, &blindingFactor);

    RCTLogInfo(@"Blind call done, retrieving blinded message from buffer");
    int blindedMessageLen = blindedMessageBuf.len;
    NSMutableData* blindedMessageData = [NSMutableData dataWithCapacity:blindedMessageLen];
    [blindedMessageData appendBytes:blindedMessageBuf.ptr length:blindedMessageLen];
    NSString *blindedMessageBase64 = [blindedMessageData base64EncodedStringWithOptions:0];
    
    RCTLogInfo(@"Cleaning Up Memory");
    free_vector(blindedMessageBuf.ptr, blindedMessageBuf.len);
    
    resolve(blindedMessageBase64);
  }
  @catch (NSException *exception) {
    RCTLogInfo(@"Exception while blinding the message: %@", exception.reason); 
    reject(@"Blinding error", exception.reason, nil);
  }
}


RCT_REMAP_METHOD(unblindMessage,
                 base64BlindedSignature:(NSString *) base64BlindedSignature
                 signerPublicKey:(NSString *) signerPublicKey
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    RCTLogInfo(@"Preparing unblind buffers");
    NSData *blindedSigData = [[NSData alloc] initWithBase64EncodedString:base64BlindedSignature options:0];
    Buffer blindedSigBuf;
    blindedSigBuf.ptr = (uint8_t*)[blindedSigData bytes];
    blindedSigBuf.len = [blindedSigData length];
    Buffer unblindedSigBuf;
    
    RCTLogInfo(@"Calling unblind");
    unblind(&blindedSigBuf, blindingFactor, &unblindedSigBuf);

    RCTLogInfo(@"Unblind call done, deserializing public key");
    NSData *publicKeyData = [signerPublicKey dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t* publicKeyBytes = (uint8_t*)[publicKeyData bytes];
    PublicKey* publicKey;
    deserialize_pubkey(publicKeyBytes, &publicKey);

    RCTLogInfo(@"Verifying the signatures");
    BOOL signatureValid = NO;
    @try {
      // Verify throws if the signatures are not correct
      verify(publicKey, &messageBuf, &unblindedSigBuf);
      signatureValid = YES;
    }
    @catch (NSException *exception) {
      reject(@"Key verification error", @"Invalid threshold signature", nil);
    }

    if (signatureValid == YES) {
      RCTLogInfo(@"Verify call done, retrieving signed message from buffer");
      int unblindedSigLen = unblindedSigBuf.len;
      NSMutableData* unblindedSigData = [NSMutableData dataWithCapacity:unblindedSigLen];
      [unblindedSigData appendBytes:unblindedSigBuf.ptr length:unblindedSigLen];
      NSString *b64UnblindedSig = [unblindedSigData base64EncodedStringWithOptions:0];
      resolve(b64UnblindedSig);
    }

    RCTLogInfo(@"Cleaning Up Memory");
    destroy_token(blindingFactor);
    blindingFactor = NULL;
    free_vector(unblindedSigBuf.ptr, unblindedSigBuf.len);
    destroy_pubkey(publicKey);
  } 
  @catch (NSException *exception) {
    RCTLogInfo(@"Exception while unblinding the signature: %@", exception.reason); 
    reject(@"Unblinding error", exception.reason, nil);
  }
}

// TODO implement a cleanup method that destroys token if user cancels btwn blinding and unblinding

@end
