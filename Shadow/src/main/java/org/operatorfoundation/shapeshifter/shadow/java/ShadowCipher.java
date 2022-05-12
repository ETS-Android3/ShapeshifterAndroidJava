package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

public abstract class ShadowCipher
{
    static int tagSize = 16;
    static int lengthWithTagSize = 2 + tagSize;
    static int tagSizeBits = tagSize * 8;
    static int maxPayloadSize = 16417;
    static int handshakeSize = 64;

    Cipher cipher;

    // [encrypted payload length][length tag] + [encrypted payload][payload tag]
    // Pack takes the data above and packs them into a singular byte array.
    public abstract byte[] pack(byte[] plaintext) throws Exception;

    // Encrypts the data and increments the nonce counter.
    abstract byte[] encrypt(byte[] plaintext) throws Exception;

    // Decrypts data and increments the nonce counter.
    public abstract byte[] decrypt(byte[] encrypted) throws Exception;

    // Create a nonce using our counter.
    public abstract byte[] nonce() throws Exception;
}
