package org.operatorfoundation.shapeshifter.shadow.java;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

// This abstract class is the superclass of all classes representing an input stream of bytes.
public class ShadowInputStream extends InputStream {
    final InputStream networkInputStream;
    final ShadowCipher decryptionCipher;
    final ShadowSocket shadowSocket;
    byte[] buffer = new byte[0];
    boolean decryptionFailed = false;


    // Applications that need to define a subclass of InputStream must always provide a method that returns the next byte of input.
    public ShadowInputStream(ShadowSocket shadowSocket, InputStream networkInputStream, ShadowCipher decryptionCipher) {
        this.networkInputStream = networkInputStream;
        this.decryptionCipher = decryptionCipher;
        this.shadowSocket = shadowSocket;
    }

    @Override
    public void close() throws IOException {
        networkInputStream.close();
    }

    // Reads some number of bytes from the input stream and stores them into the buffer array b.
    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    public int read(byte[] b) throws IOException {
        if (decryptionFailed) {
            Log.e("read", "Decryption failed on read.");
            return -1;
        }
        if (b == null || b.length == 0) {
            Log.e("read", "read was given an empty byte array.");
            return 0;
        }

        // puts the bytes in a buffer
        if (buffer.length > 0) {
            int resultSize = b.length;
            System.arraycopy(buffer, 0, b, 0, resultSize);
            buffer = Arrays.copyOfRange(buffer, resultSize, buffer.length);

            return resultSize;
        }


        //get encrypted length
        int lengthDataSize = ShadowCipher.lengthWithTagSize;

        // read bytes up to the size of encrypted lengthSize into a byte buffer
        byte[] encryptedLengthData = Utility.readNBytes(networkInputStream, lengthDataSize);
        if (encryptedLengthData == null) {
            Log.e("read", "Could not read encrypted length bytes.");
            return -1;
        }

        //decrypt encrypted length to find out payload length
        byte[] lengthData = new byte[0];
        try {
            lengthData = decryptionCipher.decrypt(encryptedLengthData);
            Log.i("read", "Length bytes decrypted.");
        } catch (Exception e) {
            e.printStackTrace();
            decryptionFailed = true;
            Log.e("read", "Decryption failed on read.");
            shadowSocket.hole.startHole(shadowSocket.holeTimeout, shadowSocket);
            shadowSocket.close();
            throw new IOException();
        }

        //change lengthData from BigEndian representation to in length
        byte leftByte = lengthData[0];
        byte rightByte = lengthData[1];
        int leftInt = (int) leftByte * 256;
        int rightInt = (int) rightByte;
        if (rightInt < 0) {
            rightInt += 256;
        }

        int payloadLength = (leftInt + rightInt);

        //read and decrypt payload with the resulting length
        byte[] encryptedPayload = Utility.readNBytes(networkInputStream, payloadLength + ShadowCipher.tagSize);
        if (encryptedPayload == null) {
            Log.e("read", "Could not read encrypted length data.");
            return -1;
        }
        byte[] payload = new byte[0];
        try {
            payload = decryptionCipher.decrypt(encryptedPayload);
            Log.i("read", "Payload decrypted.");
        } catch (Exception e) {
            e.printStackTrace();
            decryptionFailed = true;
            Log.e("read", "Decryption failed on read.");
            shadowSocket.close();
            throw new IOException();
        }
        // put payload into buffer
        buffer = Utility.plusEqualsByteArray(buffer, payload);
        assert b != null;
        int resultSize = Integer.min(b.length, buffer.length);

        // take bytes out of buffer.
        System.arraycopy(buffer, 0, b, 0, resultSize);
        buffer = Arrays.copyOfRange(buffer, resultSize, buffer.length);

        return resultSize;
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (b != null && b.length != 0) {
            byte[] readbuf = new byte[len];
            int buflen = read(readbuf);
            System.arraycopy(readbuf, off, b, 0, buflen);
            return buflen;
        } else {
            return 0;
        }
    }

    // Reads the next byte of data from the input stream.
    @RequiresApi(api = Build.VERSION_CODES.N)
    @Override
    public int read() throws IOException {
        byte[] result = new byte[0];
        // read bytes up to payload length (4)
        read(result);
        return ByteBuffer.wrap(result).getInt();
    }
}

