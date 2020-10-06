package org.operatorfoundation.shadow;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class Utility {

    // Reads up to a specific number of bytes in a byte array.
    static byte[] readNBytes(InputStream input, int numBytes) throws IOException {
        byte[] buffer = new byte[numBytes];
        int offset = input.read(buffer);
        while (offset != numBytes){
            int bytesRead = input.read(buffer, offset, numBytes - offset);
            offset = offset + bytesRead;
        }
        return buffer;
    }

    // Reads up to a specific number of bytes in a byte buffer.
    static ByteBuffer readNBytes(SocketChannel input, int numBytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(numBytes);
        byte[] bufferArray =  buffer.array();
        int offset = input.read(buffer);
        while (offset != numBytes) {
            //TODO(how in the heck do we get a ByteBuffer[] in java?!)
            //byte[] bytesRead = input.read(bufferArray, offset, numBytes - offset);
            //int bytesReadInt = ByteBuffer.wrap(bytesRead).getInt();
            //offset += bytesReadInt;
        }
        return buffer;
    }
}
