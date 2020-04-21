package org.celo;

import java.util.Random;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

import com.sun.jna.Native;
import com.sun.jna.ptr.PointerByReference;

import android.util.Log;
import android.util.Base64;

public class BlindThresholdBlsModule extends ReactContextBaseJavaModule {

    static {
        Native.register(BlindThresholdBlsModule.class, "blind_threshold_bls");
    }

    private static final String TAG = "BlindThresholdBlsModule";
    private final ReactApplicationContext reactContext;
    
    private PointerByReference blindingFactor;

    public BlindThresholdBlsModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "BlindThresholdBls";
    }

    @ReactMethod
    public void blindMessage(String message, Promise promise) {
        try {
            Log.d(TAG, "Preparing blind message buffers");
            byte[] messageBytes = message.getBytes();
            Buffer messageBuf = new Buffer(messageBytes);
            Buffer blindedMessageBuf = new Buffer();

            Log.d(TAG, "Preparing blinding seed");
            Random random = new Random();
            byte[] seed = new byte[32];
            random.nextBytes(seed);
            Buffer seedBuf = new Buffer(seed);

            Log.d(TAG, "Calling blind");
            blindingFactor = new PointerByReference();
            blind(messageBuf, seedBuf, blindedMessageBuf, blindingFactor);

            Log.d(TAG, "Blind call done, retrieving blinded message from buffer");
            byte[] blindedMessageBytes = blindedMessageBuf.getMessage();
            String b64BlindedMessage = Base64.encodeToString(blindedMessageBytes, Base64.DEFAULT);

            Log.d(TAG, "Cleaning up memory");
            // TODO call free_vector on blindedMessageBuf

            promise.resolve(b64BlindedMessage);
        } catch (Exception e) {
            Log.e(TAG, "Exception while blinding the message: " + e.getMessage());
            promise.reject(e.getMessage());
        }
    }

    @ReactMethod
    public void unblindMessage(String base64BlindedSignature, Promise promise) {
        try {
            Log.d(TAG, "Preparing unblind buffers");
            byte[] blindedSigBytes = Base64.decode(base64BlindedSignature, Base64.DEFAULT);
            Buffer blindedSigBuf = new Buffer(blindedSigBytes);
            Buffer unblindedSigBuf = new Buffer();

            Log.d(TAG, "Calling unblind");
            unblind(blindedSigBuf, blindingFactor, unblindedSigBuf);

            Log.d(TAG, "Unblind call done, retrieving signed message from buffer");
            byte[] unblindedSigBytes = unblindedSigBuf.getMessage();
            String b64UnblindedSig = Base64.encodeToString(unblindedSigBytes, Base64.DEFAULT);

            Log.d(TAG, "Verifying the signatures");
            // Verify throws if the signatures are not correct
            try {
              // TODO call verify with unblindedSigBuf and the TH pub key
            } catch (Exception e) {
              promise.reject("Invalid threshold signature");
            }

            Log.d(TAG, "Cleaning up memory");
            // TODO call destroy token for blindingFactor
            // TODO call free_vector on unblindedSigBuf

            Log.d(TAG, "Done unblinding, returning signed message");
            promise.resolve(b64UnblindedSig);
        } catch (Exception e) {
            Log.e(TAG, "Exception while unblinding the signature: " + e.getMessage());
            promise.reject(e.getMessage());
        }
    }

    // TODO implement a cleanup method that destroys token if user cancels btwn blinding and unblinding

    // private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    // protected static String bytesToHex(byte[] bytes) {
    //   char[] hexChars = new char[bytes.length * 2];
    //   for (int j = 0; j < bytes.length; j++) {
    //       int v = bytes[j] & 0xFF;
    //       hexChars[j * 2] = HEX_ARRAY[v >>> 4];
    //       hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    //   }
    //   return new String(hexChars);
    // }

    // These native methods map to the FFI bindings defined here: 
    // https://github.com/celo-org/celo-threshold-bls-rs/blob/master/ffi/threshold.h
    // Note, seed must be >= 32 characters long
    private static native void blind(Buffer message, Buffer seed, Buffer blinded_message_out, PointerByReference blinding_factor_out);
    private static native boolean unblind(Buffer blinded_signature, PointerByReference blinding_factor, Buffer unblinded_signature);
    // bool verify(const PublicKey *public_key, const Buffer *message, const Buffer *signature);
    // void free_vector(uint8_t *bytes, uintptr_t len);
    // void destroy_token(Token_PrivateKey *token);

    // private static native void deserialize_privkey(byte[] privkey, PointerByReference ptr);
    // private static native void serialize_privkey(Pointer ptr, PointerByReference pubkey_buf);
    // private static native void sign(Pointer private_key, Buffer message, Buffer signature);
}