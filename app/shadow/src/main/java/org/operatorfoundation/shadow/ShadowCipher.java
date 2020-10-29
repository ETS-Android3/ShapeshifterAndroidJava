package org.operatorfoundation.shadow;

import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ShadowCipher {
    static int saltSize = 16;
    static int lengthWithTagSize = 2 + 16;
    static int tagSizeBits = 16 * 8;
    static int tagSize = 16;
    static int maxPayloadSize = 16417;

    byte[] salt;
    Cipher cipher;
    ShadowConfig config;
    SecretKey key;
    int counter = 0;

    // ShadowCipher contains the encryption and decryption methods.
    public ShadowCipher(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {
        this.salt = salt;
        this.config = config;
        key = createSecretKey(config, salt);
        switch (config.cipherMode) {
            case AES_128_GCM:
                try {
                    cipher = Cipher.getInstance("AES_128/GCM/NoPadding");
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                break;
            case AES_256_GCM:
                try {
                    cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                break;
            case CHACHA20_IETF_POLY1305:
                try {
                    cipher = Cipher.getInstance("CHACHA20_IETF/POLY1305/NoPadding");
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                break;
        }
    }

    // Create a secret key using the two key derivation functions.
    public SecretKey createSecretKey(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {
        byte[] presharedKey = kdf(config);
        return hkdfSha1(config, salt, presharedKey);
    }

    // Key derivation functions:
    // Derives the secret key from the preshared key and adds the salt.
    public SecretKey hkdfSha1(ShadowConfig config, byte[] salt, byte[] psk) {
        String infoString = "ss-subkey";
        byte[] info = infoString.getBytes();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA1Digest());
        hkdf.init(new HKDFParameters(psk, salt, info));
        byte[] okm = new byte[psk.length];
        hkdf.generateBytes(okm, 0, psk.length);
        String keyAlgorithm = null;
        switch (config.cipherMode) {
            case AES_128_GCM:

            case AES_256_GCM:
                keyAlgorithm = "AES";
                break;

            case CHACHA20_IETF_POLY1305:
                keyAlgorithm = "ChaCha20";
                break;

            default:
                throw new IllegalStateException("Unexpected or unsupported Algorithm value: " + keyAlgorithm);
        }
        return new SecretKeySpec(okm, keyAlgorithm);
    }

    // Derives the pre-shared key from the config.
    public byte[] kdf(ShadowConfig config) throws NoSuchAlgorithmException {
        MessageDigest hash = MessageDigest.getInstance("MD5");
        byte[] buffer = new byte[0];
        byte[] prev = new byte[0];

        int keylen = 0;
        switch (config.cipherMode) {
            case AES_128_GCM:
                keylen = 16;
                break;

            case AES_256_GCM:

            case CHACHA20_IETF_POLY1305:
                keylen = 32;
                break;
        }

        while (buffer.length < keylen) {
            hash.update(prev);
            hash.update(config.password.getBytes());
            buffer = Utility.plusEqualsByteArray(buffer, hash.digest());
            int index = buffer.length - hash.getDigestLength();
            prev = Arrays.copyOfRange(buffer, index, buffer.length);
            hash.reset();
        }

        return Arrays.copyOfRange(buffer, 0, keylen);
    }

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
        Random random = new Random();
        random.nextBytes(salt);
        return salt;
    }

    // [encrypted payload length][length tag] + [encrypted payload][payload tag]
    // Pack takes the data above and packs them into a singular byte array.
    public byte[] pack(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // find the length of plaintext
        int plaintextLength = plaintext.length;

        // turn the length into two shorts and put them into an array
        // this is encoded in big endian
        short shortPlaintextLength = (short) plaintextLength;
        short leftShort = (short) (shortPlaintextLength / 256);
        short rightShort = (short) (shortPlaintextLength % 256);
        byte leftByte = (byte) (leftShort);
        byte rightByte = (byte) (rightShort);
        byte[] lengthBytes = {leftByte, rightByte};

        // encrypt the length and the payload, adding a tag to each
        byte[] encryptedLengthBytes = encrypt(lengthBytes);
        byte[] encryptedPayload = encrypt(plaintext);

        return Utility.plusEqualsByteArray(encryptedLengthBytes, encryptedPayload);
    }

    // Encrypts the data and increments the nonce counter.
    private byte[] encrypt(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] nonceBytes = nonce();
        AlgorithmParameterSpec ivSpec;
        switch (config.cipherMode) {
            case AES_128_GCM:
            case AES_256_GCM:
                ivSpec = new GCMParameterSpec(tagSizeBits, nonceBytes);
                break;

            case CHACHA20_IETF_POLY1305:
                ivSpec = new IvParameterSpec(nonceBytes);
                break;

            default:
                throw new IllegalStateException();
        }
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext);

        // increment counter every time nonce is used (encrypt/decrypt)
        counter += 1;

        return encrypted;
    }

    // Decrypts data and increments the nonce counter.
    public byte[] decrypt(byte[] encrypted) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] nonceBytes = nonce();
        AlgorithmParameterSpec ivSpec;
        switch (config.cipherMode) {
            case AES_128_GCM:
            case AES_256_GCM:
                ivSpec = new GCMParameterSpec(tagSizeBits, nonceBytes);
                break;

            case CHACHA20_IETF_POLY1305:
                ivSpec = new IvParameterSpec(nonceBytes);
                break;

            default:
                throw new IllegalStateException();
        }
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        //increment counter every time nonce is used (encrypt/decrypt)
        counter += 1;

        return cipher.doFinal(encrypted);
    }

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

        return buffer.array();
    }
}
