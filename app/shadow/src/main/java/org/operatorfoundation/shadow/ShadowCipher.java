package org.operatorfoundation.shadow;

import java.util.Random;

public class ShadowCipher {

    public ShadowCipher(ShadowConfig config, byte[] salt) {
    }

    public static byte[] createSalt(ShadowConfig config) {
        int saltSize = 0;
        switch (config.cipherMode) {
            case AES_128_GCM: {
                saltSize = 16;
                break;
            }
            case AES_256_GCM:
            case CHACHA20_IETF_POLY1305:{
                saltSize = 32;
                break;
            }
            default:
                throw new IllegalStateException("Unexpected value: " + config.cipherMode);
        }
        byte[] salt = new byte[saltSize];
        Random rando = new Random();
        return rando.nextBytes(salt);
    }

}
