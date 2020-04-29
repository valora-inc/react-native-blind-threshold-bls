package org.celo;

import java.util.Random;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
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
    private Buffer messageBuf;

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
            messageBuf = new Buffer(message.getBytes());
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
            free_vector(blindedMessageBuf.message, blindedMessageBuf.len);

            promise.resolve(b64BlindedMessage);
        } catch (Exception e) {
            Log.e(TAG, "Exception while blinding the message: " + e.getMessage());
            promise.reject(e.getMessage());
        }
    }

    @ReactMethod
    public void unblindMessage(String base64BlindedSignature, String signerPublicKey, Promise promise) {
        try {
            Log.d(TAG, "Preparing unblind buffers");
            byte[] blindedSigBytes = Base64.decode(base64BlindedSignature, Base64.DEFAULT);
            Buffer blindedSigBuf = new Buffer(blindedSigBytes);
            Buffer unblindedSigBuf = new Buffer();

            Log.d(TAG, "Calling unblind");
            unblind(blindedSigBuf, blindingFactor, unblindedSigBuf);


            Log.d(TAG, "Unblind call done, deserializing public key");
            PointerByReference publicKey = new PointerByReference();
            deserialize_pubkey(signerPublicKey.getBytes(), publicKey);

            Log.d(TAG, "Verifying the signatures");
            try {
              // Verify throws if the signatures are not correct
              verify(publicKey, messageBuf, unblindedSigBuf);
            } catch (Exception e) {
              promise.reject("Invalid threshold signature");
            }

            Log.d(TAG, "Verify call done, retrieving signed message from buffer");
            byte[] unblindedSigBytes = unblindedSigBuf.getMessage();
            String b64UnblindedSig = Base64.encodeToString(unblindedSigBytes, Base64.DEFAULT);

            Log.d(TAG, "Cleaning up memory");
            messageBuf = null;
            destroy_token(blindingFactor);
            blindingFactor = null;
            free_vector(unblindedSigBuf.message, unblindedSigBuf.len);
            destroy_pubkey(publicKey);

            Log.d(TAG, "Done unblinding, returning signed message");
            promise.resolve(b64UnblindedSig);
        } catch (Exception e) {
            Log.e(TAG, "Exception while unblinding the signature: " + e.getMessage());
            promise.reject(e.getMessage());
        }
    }

    // TODO implement a cleanup method that destroys token if user cancels btwn blinding and unblinding

    // These native methods map to the FFI bindings defined here: 
    // https://github.com/celo-org/celo-threshold-bls-rs/blob/master/ffi/threshold.h
    // Note, seed must be >= 32 characters long
    private static native void blind(Buffer message, Buffer seed, Buffer blinded_message_out, PointerByReference blinding_factor_out);
    private static native boolean unblind(Buffer blinded_signature, PointerByReference blinding_factor, Buffer unblinded_signature);
    private static native void deserialize_pubkey(byte[] pubkey_buf, PointerByReference pubkey);
    private static native boolean verify(PointerByReference public_key, Buffer message, Buffer signature);
    private static native void free_vector(Pointer bytes, int len);
    private static native void destroy_token(PointerByReference token);
    private static native void destroy_pubkey(PointerByReference public_key);
}