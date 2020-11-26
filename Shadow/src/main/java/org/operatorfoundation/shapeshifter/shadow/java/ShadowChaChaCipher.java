package org.operatorfoundation.shapeshifter.shadow.java;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.libsodium.jni.NaCl;
import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumConstants;

public class ShadowChaChaCipher extends ShadowCipher {

    public ShadowChaChaCipher(ShadowConfig config) throws NoSuchAlgorithmException {

        // Create salt for encryptionCipher
        this(config, ShadowChaChaCipher.createSalt(config));
    }

    // ShadowCipher contains the encryption and decryption methods.
    public ShadowChaChaCipher(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {

        // required to load the native C library
        NaCl.sodium();

        this.config = config;
        this.salt = salt;

        key = createSecretKey(config, salt);
        saltSize = 32;
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
        if (config.cipherMode == CipherMode.CHACHA20_IETF_POLY1305) {
            keyAlgorithm = "ChaCha20";
        } else {
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
        if (config.cipherMode == CipherMode.CHACHA20_IETF_POLY1305) {
            keylen = 32;
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

//    // Encrypts the data and increments the nonce counter.
//    byte[] encrypt(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//
//        byte[] nonceBytes = nonce();
//        AlgorithmParameterSpec ivSpec;
//        if (config.cipherMode == CipherMode.CHACHA20_IETF_POLY1305) {
//            ivSpec = new AEADParameterSpec(nonceBytes, 128);
//        } else {
//            throw new IllegalStateException();
//        }
//
//        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
//        byte[] encrypted = cipher.doFinal(plaintext);
//
//        // increment counter every time nonce is used (encrypt/decrypt)
//        counter += 1;
//
//        return encrypted;
//    }

    // Encrypts the data and increments the nonce counter.
    @Override
    byte[] encrypt(byte[] plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // cipherText should be at least crypto_box_MACBYTES + messageBytes.length bytes long
        int plaintext_length = plaintext.length;
        int[] ciphertext_length = {plaintext.length + Sodium.crypto_aead_chacha20poly1305_ietf_abytes()};
        byte[] ciphertext = new byte[ciphertext_length[0]];
        byte[] nonceBytes = nonce();
        byte[] additional = new byte[0];
        int additional_length = 0;

        Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
                ciphertext, ciphertext_length,
                plaintext, plaintext_length,
                additional, additional_length,
                null, nonceBytes, key.getEncoded()
        );

        // Return nonce + cipher text
        byte[] fullMessage = new byte[nonceBytes.length + ciphertext.length];
        System.arraycopy(nonceBytes, 0, fullMessage, 0, nonceBytes.length);
        System.arraycopy(ciphertext, 0, fullMessage, nonceBytes.length, ciphertext.length);

        // increment counter every time nonce is used (encrypt/decrypt)
        counter += 1;

        return fullMessage;
    }

    // Decrypts data and increments the nonce counter.
    @Override
    public byte[] decrypt(byte[] encrypted) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] additional = new byte[0];
        int additional_length = 0;

        // Get the nonce from the encrypted bytes
        byte[] nonce = new byte[SodiumConstants.NONCE_BYTES];
        System.arraycopy(encrypted, 0, nonce, 0, nonce.length);

        // get the cipher text from the encrypted bytes
        byte[] ciphertext = new byte[encrypted.length - nonce.length];
        System.arraycopy(encrypted, nonce.length, ciphertext, 0, ciphertext.length);

        int[] plaintext_length = {ciphertext.length - Sodium.crypto_aead_chacha20poly1305_ietf_abytes()};
        byte[] plaintext = new byte[plaintext_length[0]];

        Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext, plaintext_length,
                null,
                ciphertext, ciphertext.length,
                additional, additional_length,
                key.getEncoded(), nonce
        );

        //increment counter every time nonce is used (encrypt/decrypt)
        counter += 1;

        return plaintext;
    }

//    public byte[] decrypt(byte[] encrypted) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        byte[] nonceBytes = nonce();
//        AlgorithmParameterSpec ivSpec;
//        if (config.cipherMode == CipherMode.CHACHA20_IETF_POLY1305) {
//            ivSpec = new AEADParameterSpec(nonceBytes, 128);
//        } else {
//            throw new IllegalStateException();
//        }
//        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
//
//        //increment counter every time nonce is used (encrypt/decrypt)
//        counter += 1;
//
//        return cipher.doFinal(encrypted);
//    }

}
