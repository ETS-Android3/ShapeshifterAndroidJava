package org.operatorfoundation.shadow;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class ShadowInputStream {
    final InputStream networkInputStream;
    final ShadowCipher decryptionCipher;
    byte[] buffer = new byte[0];

    public ShadowInputStream(InputStream networkInputStream, ShadowCipher decryptionCipher) {
        this.networkInputStream = networkInputStream;
        this.decryptionCipher = decryptionCipher;
    }

    public int read(byte[] b) throws IOException {
        if (b != null && b.length > 0) {

            // puts the bytes in a buffer
            if (b.length <= buffer.length) {
                int resultSize = Integer.min(b.length, buffer.length);
                System.arraycopy(b, 0, buffer, 0, resultSize);
                //TODO(just like in OutputStream, not sure if this sub for sliceArray will work)
                buffer = Arrays.copyOfRange(buffer, resultSize + 1, buffer.length + 1);

                return resultSize;
            }

            //get encrypted length
            int lengthDataSize = ShadowCipher.lengthWithTagSize;

            // read bytes up to the size of encrypted lengthSize into a byte buffer
            byte[] encryptedLengthData = Utility.readNBytes(networkInputStream, lengthDataSize);

            //decrypt encrypted length to find out payload length
            byte[] lengthData = decryptionCipher.decrypt(encryptedLengthData);

            //change lengthData from BigEndian representation to in length
            byte leftByte = lengthData[0];
            byte rightByte = lengthData[1];
            int payloadLength = ((int) leftByte * 256) + (int) rightByte;

            //read and decrypt payload with the resulting length
            byte[] encryptedPayload = Utility.readNBytes(networkInputStream, payloadLength + ShadowCipher.tagSize);
            byte[] payload = decryptionCipher.decrypt(encryptedPayload);


            //TODO(not sure how to do the copyInto and sliceArray to put payload into buffer and take it out)
            //TODO(figure out the += for byte arrays)

            return Integer.min(b.length, buffer.length);
        }
        //TODO(im truly at a loss for this class)
        return 0;
    }

    public int read() throws IOException {
        byte[] result = new byte[0];
        read(result);
        return ByteBuffer.wrap(result).getInt();
    }
}

