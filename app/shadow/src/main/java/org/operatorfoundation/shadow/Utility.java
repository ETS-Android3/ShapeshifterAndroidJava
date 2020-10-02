package org.operatorfoundation.shadow;

import java.io.IOException;
import java.io.InputStream;

public class Utility {

    static byte[] readNBytes(InputStream input, int numBytes) throws IOException {
        byte[] buffer = new byte[numBytes];
        int offset = input.read(buffer);
        while (offset != numBytes){
            int bytesRead = input.read(buffer, offset, numBytes - offset);
            offset = offset + bytesRead;
        }
        return buffer;
    }
}
