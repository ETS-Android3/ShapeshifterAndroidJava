package org.operatorfoundation.shapeshifter.shadow.java;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

// This abstract class is the superclass of all classes representing an output stream of bytes.
public class ShadowOutputStream extends OutputStream {
    OutputStream outputStream;
    ShadowCipher encryptionCipher;
    byte[] buffer = new byte[0];

    // An output stream accepts output bytes and sends them to some sink.
    public ShadowOutputStream(OutputStream outputStream, ShadowCipher encryptionCipher) {
        this.outputStream = outputStream;
        this.encryptionCipher = encryptionCipher;
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    // Writes the specified byte to this output stream.
    @Override
    public void write(int b) throws IOException {
        byte[] plainText = new byte[b];
        write(plainText);
    }

    // Writes b.length bytes from the specified byte array to this output stream.
    @Override
    public void write(byte[] b) throws IOException {
        if (b != null && b.length > 0) {

            // put into buffer
            buffer = Utility.plusEqualsByteArray(buffer, b);
            int offset = 0;
            while (offset < buffer.length) {
                int numBytesToSend = Math.min(ShadowCipher.maxPayloadSize, buffer.length - offset);

                // take bytes out of buffer
                byte[] bytesToSend = new byte[numBytesToSend];
                System.arraycopy(buffer, offset, bytesToSend, 0, numBytesToSend);

                byte[] cipherText = new byte[0];
                try {
                    cipherText = encryptionCipher.pack(bytesToSend);
                } catch (Exception e) {
                    Log.e("write", "Failed to pack bytes.");
                    e.printStackTrace();
                }
                outputStream.write(cipherText);
                outputStream.flush();

                offset += numBytesToSend;
                Log.i("write", "Write successful.");
            }
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (b != null && b.length != 0) {
            byte[] buf = Arrays.copyOfRange(b, off, len);
            write(buf);
        }
    }

    // Flushes this output stream and forces any buffered output bytes to be written out.
    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }
}
