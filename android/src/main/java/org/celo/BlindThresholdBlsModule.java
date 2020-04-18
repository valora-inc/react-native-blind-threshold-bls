package org.celo;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;

import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

import android.util.Log;

public class BlindThresholdBlsModule extends ReactContextBaseJavaModule {

    static {
        Native.register(BlindThresholdBlsModule.class, "blind_threshold_bls");
    }

// TODO cleanup
//    class BlindedMessage {
//        public Buffer message;
//        public String blinding_factor;
//
//        BlindedMessage(Buffer message, String blinding_factor) {
//            this.message = message;
//            this.blinding_factor = blinding_factor;
//        }
//    }

    private static final String TAG = "BlindThresholdBlsModule";
    private final ReactApplicationContext reactContext;

    public BlindThresholdBlsModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "BlindThresholdBls";
    }

    @ReactMethod
    public void blindMessage(String message, Callback callback) {
        try {
            Log.d(TAG, "Blinding message" );
            byte[] buffer = new byte[512];
            IntByReference bufferSize = new IntByReference(buffer.length);
            blind(message, "my awesome seed must be at least 32 characters long", buffer, bufferSize);
            Log.d(TAG, "Received buffer size: " + bufferSize.getValue() );
            String blinded = new String(buffer, 0, bufferSize.getValue());
            Log.d(TAG, "Received blinded message: " + blinded );
            callback.invoke(blinded);
        } catch (Exception e) {
            Log.e(TAG, "Exception while blinding the message: " + e.getMessage() );
        }

    }

    // Seed must be >= 32 characters long
    private static native void blind(String message, String seed, byte[] blinded_message, IntByReference blinded_message_size);
}