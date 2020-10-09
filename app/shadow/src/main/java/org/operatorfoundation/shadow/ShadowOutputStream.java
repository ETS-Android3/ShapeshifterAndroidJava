package org.operatorfoundation.shadow;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

// This abstract class is the superclass of all classes representing an output stream of bytes.
public class ShadowOutputStream {
    final OutputStream outputStream;
    final ShadowCipher encryptionCipher;
    byte[] buffer = new byte[0];

    // An output stream accepts output bytes and sends them to some sink.
    public ShadowOutputStream(OutputStream outputStream, ShadowCipher encryptionCipher) {
        this.outputStream = outputStream;
        this.encryptionCipher = encryptionCipher;
    }

    // Writes the specified byte to this output stream.
    public void write(int b) throws IOException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        byte[] plainText = new byte[b];
        write(plainText);
    }

    // Writes b.length bytes from the specified byte array to this output stream.
    public void write(byte[] b) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        if (b != null && b.length > 0) {

            // put into buffer
            //TODO(it wont let me use the += so this is just a placeholder)
            buffer = b;
            int offset = 0;
            while (offset < buffer.length) {
                int numBytesToSend = Integer.min(ShadowCipher.maxPayloadSize, buffer.length - offset);

                // take bytes out of buffer
                byte[] bytesToSend = new byte[numBytesToSend];
                System.arraycopy(buffer, offset, bytesToSend, 0, numBytesToSend);

                byte[] cipherText = encryptionCipher.pack(bytesToSend);
                outputStream.write(cipherText);

                offset += numBytesToSend;
            }
        }
    }

    // Flushes this output stream and forces any buffered output bytes to be written out.
    public void flush() throws IOException {
        outputStream.flush();
    }
}
