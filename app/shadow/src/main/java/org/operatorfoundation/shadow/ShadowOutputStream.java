package org.operatorfoundation.shadow;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class ShadowOutputStream {
    final OutputStream outputStream;
    final ShadowCipher encryptionCipher;
    byte[] buffer = new byte[0];

    public ShadowOutputStream(OutputStream outputStream, ShadowCipher encryptionCipher) {
        this.outputStream = outputStream;
        this.encryptionCipher = encryptionCipher;
    }

    public void write(int b) throws IOException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        byte[] plainText = new byte[b];
        write(plainText);
    }

    public void write(byte[] b) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        if (b != null && b.length > 0) {
            //TODO(it wont let me use the += so this is just a placeholder)
            buffer = b;
            while (buffer.length > 0) {
                int numBytesToSend = Integer.min(ShadowCipher.maxPayloadSize, buffer.length);
                //TODO(since sliceArray isn't here, this is what i found to work)
                //TODO(copyOfRange is inclusive while the original was inclusive.  double check that the -1 is correct)
                byte[] bytesToSend = Arrays.copyOfRange(buffer, numBytesToSend, buffer.length - 1);

                byte[] cipherText = encryptionCipher.pack(bytesToSend);
                outputStream.write(cipherText);
            }
        }
    }

    public void flush() throws IOException {
        outputStream.flush();
    }
}
