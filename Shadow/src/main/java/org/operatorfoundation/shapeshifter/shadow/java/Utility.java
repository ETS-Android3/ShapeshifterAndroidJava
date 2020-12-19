package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class Utility {

    // Reads up to a specific number of bytes in a byte array.
    static byte[] readNBytes(InputStream input, int numBytes) throws IOException {
        byte[] buffer = new byte[numBytes];
        int offset = input.read(buffer);
        if (offset == -1) {
            return null;
        }
        while (offset != numBytes) {
            int bytesRead = input.read(buffer, offset, numBytes - offset);
            if (bytesRead == -1) {
                return null;
            }
            offset = offset + bytesRead;
        }
        return buffer;
    }

    // Reads up to a specific number of bytes in a byte buffer.
    static ByteBuffer readNBytes(SocketChannel input, int numBytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(numBytes);
        ByteBuffer[] bufferArray = new ByteBuffer[]{buffer};
        int offset = input.read(buffer);
        while (offset != numBytes) {
            long bytesRead = input.read(bufferArray, offset, numBytes - offset);
            int bytesReadInt = (int) bytesRead;
            offset += bytesReadInt;
        }
        return buffer;
    }

    static byte[] plusEqualsByteArray(byte[] one, byte[] two) {
        byte[] combined = new byte[one.length + two.length];

        System.arraycopy(one, 0, combined, 0, one.length);
        System.arraycopy(two, 0, combined, one.length, two.length);
        return combined;
    }
}
