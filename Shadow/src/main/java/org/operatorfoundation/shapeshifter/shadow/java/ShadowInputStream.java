package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

// This abstract class is the superclass of all classes representing an input stream of bytes.
public class ShadowInputStream extends InputStream {
    InputStream networkInputStream;
    ShadowCipher decryptionCipher;
    ShadowSocket shadowSocket;
    byte[] buffer = new byte[0];
    boolean decryptionFailed = false;
    boolean firstRead = true;


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
    @Override
    public int read(byte[] outputBuffer) throws IOException
    {
        if (decryptionFailed)
        {
            Log.e("ShadowInputStream.read", "Decryption failed on read.");
            shadowSocket.close();
            throw new IOException();
        }

        if (outputBuffer == null || outputBuffer.length == 0)
        {
            Log.e("ShadowInputStream.read", "read was given an empty or null byte array.");
            return 0;
        }

        // if the class buffer already has data, put it in the output buffer
        int returnSize = outputBuffer.length;
        int bufferSize = buffer.length;

        if (returnSize <= bufferSize)
        {
            System.arraycopy(buffer, 0, outputBuffer, 0, returnSize);
            buffer = Arrays.copyOfRange(buffer, returnSize, bufferSize);

            return outputBuffer.length;
        }
        else if (bufferSize > 0)
        {
            // we were passed an array that is bigger than what we already stored in the buffer
            // but the buffer isn't empty, so lets pass what's in our buffer back to the caller
            System.arraycopy(buffer, 0, outputBuffer, 0, bufferSize);

            // Empty our buffer now that we've handed off all of the data in it
            buffer = new byte[0];

            return outputBuffer.length;
        }

        try
        {
            //get encrypted length
            int lengthDataSize = ShadowCipher.lengthWithTagSize;
            Log.d("ShadowInputStream.read", "attempting to read length data.");

            // read bytes up to the size of encrypted lengthSize into a byte buffer
            byte[] encryptedLengthData = Utility.readNBytes(networkInputStream, lengthDataSize);
            if (encryptedLengthData == null)
            {
                Log.e("ShadowInputStream.read", "Could not read encrypted length bytes.");
                return -1;
            }
            Log.d("ShadowInputStream.read", "read length data.");

            //decrypt encrypted length to find out payload length
            byte[] lengthData = decryptionCipher.decrypt(encryptedLengthData);
            firstRead = false;
            Log.d("ShadowInputStream.read", "Length bytes decrypted.");

            // change lengthData from BigEndian representation to int length
            int payloadLength = Utility.getIntFromBigEndian(lengthData);
            Log.d("Shadow.DecryptedLength", Integer.toString(payloadLength));

            //read and decrypt payload with the resulting length
            byte[] encryptedPayload = Utility.readNBytes(networkInputStream, payloadLength + ShadowCipher.tagSize);
            if (encryptedPayload == null)
            {
                Log.e("ShadowInputStream.read", "Could not read encrypted length data.");
                return -1;
            }

            byte[] payload;
            payload = decryptionCipher.decrypt(encryptedPayload);
            Log.i("ShadowInputStream.read", "Payload decrypted.");

            // put payload into buffer
            buffer = Utility.plusEqualsByteArray(buffer, payload);
            int resultSize = Math.min(outputBuffer.length, buffer.length);

            // take bytes out of buffer.
            System.arraycopy(buffer, 0, outputBuffer, 0, resultSize);
            buffer = Arrays.copyOfRange(buffer, resultSize, buffer.length);

            return resultSize;
        }
        catch (DarkStarDecryptionException decryptError)
        {
            Log.e("ShadowInputStream.read", "Decryption failed.");

            try
            {
                if (firstRead)
                {
                    // Try to redial
                    shadowSocket.dial(shadowSocket.shadowConfig, shadowSocket.host, shadowSocket.port);
                }
                else
                {
                    // Give up
                    decryptionFailed = true;
                    shadowSocket.close();
                    Log.e("ShadowInputStream.read", "Decryption Error, closing the connection.");
                    throw new IOException();
                }
            }
            catch (Exception dialError)
            {
                // If the redial fails, give up
                Log.e("ShadowInputStream.read", "Received an Exception.");
                dialError.printStackTrace();
                throw new IOException();
            }

            throw new IOException();
        }
        catch (Exception readError)
        {
            if (readError instanceof IOException) // readNBytes failed
            {
                Log.e("ShadowInputStream.read", "Received an IOException.");
                shadowSocket.close();
            }

            readError.printStackTrace();
            throw new IOException();
        }

    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        if (b != null && b.length != 0)
        {
            byte[] readbuf = new byte[len];
            int buflen = read(readbuf);
            System.arraycopy(readbuf, off, b, 0, buflen);

            return buflen;
        }
        else
        {
            return 0;
        }
    }

    // Reads the next byte of data from the input stream.
    @Override
    public int read() throws IOException
    {
        byte[] result = new byte[0];

        // read bytes up to payload length (4)
        read(result);

        return ByteBuffer.wrap(result).getInt();
    }


}

