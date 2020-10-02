package org.operatorfoundation.shadow;

import java.util.Random;

public class ShadowCipher {
    static int lengthWithTagSize = 2 + 16;
    static int tagSizeBits = 16 * 8;
    static int tagSize = 16;
    static int maxPayloadSize = 16417;
    //TODO(Could i set the saltSize static variable in a switch loop)
    static int saltSize = 16;

    public ShadowCipher(ShadowConfig config, byte[] salt) {
    }

    //TODO(JAVA DOESNT HAVE COMPANION OBJECTSSSSSS!!!!!!)
    public static byte[] createSalt(ShadowConfig config) {
        int saltSize;
        switch (config.cipherMode) {
            case AES_128_GCM: {
                saltSize = 16;
                break;
            }
            case AES_256_GCM:
            case CHACHA20_IETF_POLY1305: {
                saltSize = 32;
                break;
            }
            default:
                throw new IllegalStateException("Unexpected value: " + config.cipherMode);
        }
        byte[] salt = new byte[saltSize];
        Random random = new Random();
        random.nextBytes(salt);
        return salt;
    }

    public byte[] pack(byte[] bytesToSend) {
        return bytesToSend;
    }

    public byte[] decrypt(byte[] encryptedLengthData) {
        return encryptedLengthData;
    }
}
