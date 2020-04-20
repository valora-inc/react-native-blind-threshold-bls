package org.celo;

import java.util.Random;
import org.celo.Buffer;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.sun.jna.Native;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import android.util.Log;

public class BlindThresholdBlsModule extends ReactContextBaseJavaModule {

    static {
        Native.register(BlindThresholdBlsModule.class, "blind_threshold_bls");
    }

    private static final String TAG = "BlindThresholdBlsModule";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
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
            Log.d(TAG, "Start blindMessage" );
            Random random = new Random();
            byte[] seed = new byte[32];
            random.nextBytes(seed);
            Log.d(TAG, "stuff -2");
            byte[] messageBytes = message.getBytes();
            Buffer msg = new Buffer(messageBytes);
            Log.d(TAG, "stuff -1");
            Buffer seedBuf = new Buffer(seed);
            Buffer blindedMessage = new Buffer();
            PointerByReference token = new PointerByReference();
            blind(msg, seedBuf, blindedMessage, token);
            Log.d(TAG, "stuff 0");

            PointerByReference pDev = new PointerByReference();
            deserialize_privkey(seed, pDev);
            Log.d(TAG, "ptr: " + pDev.getValue());
            PointerByReference buffer = new PointerByReference();
            serialize_privkey(pDev.getValue(), buffer);
            Log.d(TAG, "stuff 1: " + buffer.getValue());
            Log.d(TAG, "stuff 2: " + bytesToHex(buffer.getValue().getByteArray(0, 32)));

            Buffer sig = new Buffer();
            sign(pDev.getValue(), blindedMessage, sig);
            sig.read();
            Log.d(TAG, "stuff 3: " + sig.len);
            Log.d(TAG, "stuff 3: " + bytesToHex(sig.message.getByteArray(0, 193)));

            Log.d(TAG, "End blindMessage, passing result to callback" );
            // TODO return blinded, signed message?
            // callback.invoke(blinded);

        } catch (Exception e) {
            Log.e(TAG, "Exception while blinding the message: " + e.getMessage() );
        }
    }

    protected static String bytesToHex(byte[] bytes) {
      char[] hexChars = new char[bytes.length * 2];
      for (int j = 0; j < bytes.length; j++) {
          int v = bytes[j] & 0xFF;
          hexChars[j * 2] = HEX_ARRAY[v >>> 4];
          hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
      }
      return new String(hexChars);
    }

    // Seed must be >= 32 characters long
    private static native void deserialize_privkey(byte[] privkey, PointerByReference ptr);
    private static native void serialize_privkey(Pointer ptr, PointerByReference pubkey_buf);
    private static native void sign(Pointer private_key, Buffer message, Buffer signature);
    private static native void blind(Buffer message, Buffer seed, Buffer blinded_message_out, PointerByReference blinding_factor_out);
}