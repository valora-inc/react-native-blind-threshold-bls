#import "BlindThresholdBls.h"
#import "Headers/threshold.h"
#import <React/RCTLog.h>
#import <Foundation/Foundation.h>
#import <stdlib.h>
#import <stdint.h>

@implementation BlindThresholdBls {
  Token_PrivateKey* blindingFactor;
  NSData* messageData;
}

RCT_EXPORT_MODULE()

// TODO add support for multiple outstanding blind calls
RCT_REMAP_METHOD(blindMessage,
                 message:(NSString *) message
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    RCTLogInfo(@"Preparing blind message buffers");
    messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    Buffer messageBuf;
    messageBuf.ptr = (uint8_t*)[messageData bytes];
    messageBuf.len = [messageData length];

    Buffer blindedMessageBuf;
    blindedMessageBuf.ptr = NULL;
    blindedMessageBuf.len = 0;
    
    RCTLogInfo(@"Preparing blinding seed");
    NSMutableData* seedData = [NSMutableData dataWithCapacity:32];
    int status = SecRandomCopyBytes(kSecRandomDefault, 32, seedData.mutableBytes);
    if (status != errSecSuccess) {
      [NSException raise:@"Random bytes copy failed" format:@"status code %d", status];
    }
    Buffer seedBuf;
    seedBuf.ptr = (uint8_t*)[seedData bytes];
    seedBuf.len = 32;

    RCTLogInfo(@"Calling blind");
    blind(&messageBuf, &seedBuf, &blindedMessageBuf, &blindingFactor);

    RCTLogInfo(@"Blind call done, retrieving blinded message from buffer");
    int blindedMessageLen = blindedMessageBuf.len;
    uint8_t* blindedMessagePtr = blindedMessageBuf.ptr;
    NSMutableData* blindedMessageData = [NSMutableData dataWithCapacity:blindedMessageLen];
    [blindedMessageData appendBytes:blindedMessagePtr length:blindedMessageLen];
    NSString *blindedMessageBase64 = [blindedMessageData base64EncodedStringWithOptions:0];
    
    RCTLogInfo(@"Cleaning Up Memory");
    free_vector(blindedMessagePtr, blindedMessageLen);
    
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
    unblindedSigBuf.ptr = NULL;
    unblindedSigBuf.len = 0;
    
    RCTLogInfo(@"Calling unblind");
    unblind(&blindedSigBuf, blindingFactor, &unblindedSigBuf);

    RCTLogInfo(@"Unblind call done, deserializing public key");
    NSData *publicKeyData = [signerPublicKey dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t* publicKeyBytes = (uint8_t*)[publicKeyData bytes];
    PublicKey* publicKey;
    deserialize_pubkey(publicKeyBytes, &publicKey);

    RCTLogInfo(@"Verifying the signatures");
    BOOL signatureValid = NO;
    // Verify throws if the signatures are not correct
    @try {
      Buffer messageBuf;
      messageBuf.ptr = (uint8_t*)[messageData bytes];
      messageBuf.len = [messageData length];
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
    messageData = NULL;
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
