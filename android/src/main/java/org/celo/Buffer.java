package org.celo;

import java.util.List;
import java.util.Arrays;

import com.sun.jna.Structure;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;

public class Buffer extends Structure {

    public Pointer message;
    public int len;

    public Buffer() {}

    public Buffer(byte[] in_message) { 
      message = new Memory(in_message.length); 
      message.write(0, in_message, 0, in_message.length); 
      len = in_message.length; 
    }

    public List<String> getFieldOrder() {
        return Arrays.asList("message", "len");
    }
}