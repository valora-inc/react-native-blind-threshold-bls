#import "BlindThresholdBls.h"
#import "Headers/threshold.h"
#import <React/RCTLog.h>
#import <Foundation/Foundation.h>
#import <stdlib.h>

@implementation BlindThresholdBls {
  Token_PrivateKey* blindingFactor;
  Buffer messageBuf;
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
    NSData *messageData = [[NSData alloc] initWithBase64EncodedString:message options:0];
    messageBuf.ptr = [BlindThresholdBls nsDataToByteArray:messageData];
    messageBuf.len = [messageData length];

    Buffer blindedMessageBuf;
    blindedMessageBuf.ptr = NULL;
    blindedMessageBuf.len = 0;
    
    RCTLogInfo(@"Preparing blinding seed");
    uint8_t *seedData = malloc(sizeof(uint8_t) * 32);
    int status = SecRandomCopyBytes(kSecRandomDefault, 32, seedData);
    if (status != errSecSuccess) {
      [NSException raise:@"Random bytes copy failed" format:@"status code %d", status];
    }
    Buffer seedBuf;
    seedBuf.ptr = seedData;
    seedBuf.len = 32;

    RCTLogInfo(@"Calling blind");
    blind(&messageBuf, &seedBuf, &blindedMessageBuf, &blindingFactor);

    RCTLogInfo(@"Blind call done, retrieving blinded message from buffer");
    const size_t blindedMessageLen = blindedMessageBuf.len;
    const uint8_t* blindedMessagePtr = blindedMessageBuf.ptr;
    NSMutableData* blindedMessageData = [NSMutableData dataWithCapacity:blindedMessageLen];
    [blindedMessageData appendBytes:blindedMessagePtr length:blindedMessageLen];
    NSString *blindedMessageBase64 = [blindedMessageData base64EncodedStringWithOptions:0];
    
    RCTLogInfo(@"Cleaning Up Memory");
    free_vector(blindedMessagePtr, blindedMessageLen);
    free(seedBuf.ptr);
    
    resolve(blindedMessageBase64);
  }
  @catch (NSException *exception) {
    RCTLogInfo(@"Exception while blinding the message: %@", exception.reason); 
    reject(@"Blinding error", exception.reason, nil);
  }
}


RCT_REMAP_METHOD(unblindMessage,
                 base64BlindedSignature:(NSString *) base64BlindedSignature
                 base64SignerPublicKey:(NSString *) base64SignerPublicKey
                 resolver:(RCTPromiseResolveBlock)resolve
                 rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    RCTLogInfo(@"Preparing unblind buffers");
    NSData *blindedSigData = [[NSData alloc] initWithBase64EncodedString:base64BlindedSignature options:0];
    Buffer blindedSigBuf;
    blindedSigBuf.ptr = [BlindThresholdBls nsDataToByteArray:blindedSigData];
    blindedSigBuf.len = [blindedSigData length];

    Buffer unblindedSigBuf;
    unblindedSigBuf.ptr = NULL;
    unblindedSigBuf.len = 0;
    
    RCTLogInfo(@"Calling unblind");
    unblind(&blindedSigBuf, blindingFactor, &unblindedSigBuf);

    RCTLogInfo(@"Unblind call done, deserializing public key");
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:base64SignerPublicKey options:0];
    uint8_t* publicKeyBytes = [BlindThresholdBls nsDataToByteArray:publicKeyData];
    PublicKey* publicKey = NULL;
    deserialize_pubkey(publicKeyBytes, &publicKey);

    RCTLogInfo(@"Verifying the signatures");
    bool signatureValid = false;
    // Verify may throw if the signatures are not correct
    @try {
      signatureValid = verify(publicKey, &messageBuf, &unblindedSigBuf);
    }
    @catch (NSException *exception) {
      signatureValid = false;
      RCTLogInfo(@"Invalid threshold signature found when verifying");
    }

    if (signatureValid == true) {
      RCTLogInfo(@"Verify call done, retrieving signed message from buffer");
      const size_t unblindedSigLen = unblindedSigBuf.len;
      NSMutableData* unblindedSigData = [NSMutableData dataWithCapacity:unblindedSigLen];
      [unblindedSigData appendBytes:unblindedSigBuf.ptr length:unblindedSigLen];
      NSString *b64UnblindedSig = [unblindedSigData base64EncodedStringWithOptions:0];
      resolve(b64UnblindedSig);
    }
    else {
      reject(@"Key verification error", @"Invalid threshold signature", nil);
    }

    RCTLogInfo(@"Cleaning Up Memory");
    free_vector(unblindedSigBuf.ptr, unblindedSigBuf.len);
    destroy_token(blindingFactor);
    blindingFactor = NULL;
    destroy_pubkey(publicKey);
    free(publicKeyBytes);
    free(blindedSigBuf.ptr);
    free(messageBuf.ptr);
    messageBuf.ptr = NULL;
    messageBuf.len = 0;
   
  } 
  @catch (NSException *exception) {
    RCTLogInfo(@"Exception while unblinding the signature: %@", exception.reason); 
    reject(@"Unblinding error", exception.reason, nil);
  }
}

+ (uint8_t*) nsDataToByteArray: (NSData*)data
{
  NSUInteger len = [data length];
  uint8_t *byteData = malloc(sizeof(uint8_t) * len);
  [data getBytes:byteData length:len];
  return byteData;
}

// TODO implement a cleanup method that destroys token if user cancels btwn blinding and unblinding

@end
