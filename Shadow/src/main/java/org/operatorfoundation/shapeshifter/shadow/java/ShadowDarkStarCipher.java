package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class ShadowDarkStarCipher extends ShadowCipher {
SecretKey key;
byte[] nonce;

    // ShadowCipher contains the encryption and decryption methods.
    public ShadowDarkStarCipher(SecretKey key, byte[] nonce) throws NoSuchAlgorithmException {
        this.key = key;
        this.nonce = nonce;

        try {
            cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
            saltSize = 32;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    // Create a secret key using the two key derivation functions.
    public SecretKey createSecretKey(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {
        // FIXME: Actually refactor this function
        //DarkStar.generateSharedKeyClient(config.cipherName, config.password, salt);
        return null;
    }

    @Override
    public SecretKey hkdfSha1(ShadowConfig config, byte[] salt, byte[] psk) {
        return null;
    }

    @Override
    public byte[] kdf(ShadowConfig config) throws NoSuchAlgorithmException {
        return new byte[0];
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
    byte[] encrypt(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        AlgorithmParameterSpec ivSpec;
        ivSpec = new GCMParameterSpec(tagSizeBits, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        return cipher.doFinal(plaintext);
    }

    // Decrypts data and increments the nonce counter.
    public byte[] decrypt(byte[] encrypted) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        AlgorithmParameterSpec ivSpec;
        ivSpec = new GCMParameterSpec(tagSizeBits, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(encrypted);
    }
}
