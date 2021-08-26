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

public abstract class ShadowCipher {
    static int lengthWithTagSize = 2 + 16;
    static int tagSizeBits = 16 * 8;
    static int tagSize = 16;
    static int maxPayloadSize = 16417;
    private static int finalSaltSize;

    byte[] salt;
    int saltSize;
    Cipher cipher;
    ShadowConfig config;
    SecretKey key;
    int counter = 0;

    static ShadowCipher makeShadowCipher(ShadowConfig config) throws NoSuchAlgorithmException {
        switch (config.cipherMode) {
            case AES_128_GCM:

            case AES_256_GCM:
                return new ShadowAESCipher(config);

            case CHACHA20_IETF_POLY1305:
                return new ShadowChaChaCipher(config);

            default:
                throw new IllegalStateException("Unexpected or unsupported Algorithm value");
        }

    }

    static ShadowCipher makeShadowCipherWithSalt(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {
        switch (config.cipherMode) {
            case AES_128_GCM:

            case AES_256_GCM:
                return new ShadowAESCipher(config, salt);
            //break;

            case CHACHA20_IETF_POLY1305:
                return new ShadowChaChaCipher(config, salt);
            //break;

            default:
                throw new IllegalStateException("Unexpected or unsupported Algorithm value");
        }

    }

    static int determineSaltSize(ShadowConfig config) {
        switch (config.cipherMode) {
            case AES_128_GCM:
                finalSaltSize = 16;
                break;
            case AES_256_GCM:
            case CHACHA20_IETF_POLY1305:
                finalSaltSize = 32;
                break;
        }
        Log.i("determineSaltSize", "Salt size is $finalSaltSize");
        return finalSaltSize;
    }

    // Create a secret key using the two key derivation functions.
    public abstract SecretKey createSecretKey(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException;

    // Key derivation functions:
    // Derives the secret key from the preshared key and adds the salt.
    public abstract SecretKey hkdfSha1(ShadowConfig config, byte[] salt, byte[] psk);

    // Derives the pre-shared key from the config.
    public abstract byte[] kdf(ShadowConfig config) throws NoSuchAlgorithmException;

    // Creates a byteArray of a specified length containing random bytes.
    public static byte[] createSalt(ShadowConfig config) {
        int saltSize;
        switch (config.cipherMode) {
            case AES_128_GCM:
                saltSize = 16;
                break;

            case AES_256_GCM:
            case CHACHA20_IETF_POLY1305:
                saltSize = 32;
                break;

            default:
                throw new IllegalStateException("Unexpected value: " + config.cipherMode);
        }
        byte[] salt = new byte[saltSize];
        Random random = new java.security.SecureRandom();
        random.nextBytes(salt);
        Log.i("createSalt", "Salt created.");
        return salt;
    }

    // [encrypted payload length][length tag] + [encrypted payload][payload tag]
    // Pack takes the data above and packs them into a singular byte array.
    public abstract byte[] pack(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    // Encrypts the data and increments the nonce counter.
    abstract byte[] encrypt(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    // Decrypts data and increments the nonce counter.
    public abstract byte[] decrypt(byte[] encrypted) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    // Create a nonce using our counter.
    public byte[] nonce() {
        // nonce must be 12 bytes
        ByteBuffer buffer = ByteBuffer.allocate(12);
        // nonce is little Endian
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        // create a byte array from counter
        buffer.putLong(counter);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        Log.i("nonce", "Nonce created. Counter is $counter.");
        return buffer.array();
    }
}
