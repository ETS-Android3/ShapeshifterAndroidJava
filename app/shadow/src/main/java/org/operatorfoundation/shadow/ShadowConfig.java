package org.operatorfoundation.shadow;

public class ShadowConfig {
    final String password;
    final String cipherName;
    public CipherMode cipherMode;

    public ShadowConfig(String password, String cipherName) {
        this.password = password;
        this.cipherName = cipherName;

        {
            CipherMode maybeMode = null;
            try {
                switch (cipherName) {
                    case "AES-128-GCM": {
                        maybeMode = CipherMode.AES_128_GCM;
                        break;
                    }
                    case "AES-256-GCM": {
                        maybeMode = CipherMode.AES_256_GCM;
                        break;
                    }
                    case "CHACHA-IETF-POLY1305": {
                        maybeMode = CipherMode.CHACHA20_IETF_POLY1305;
                        break;
                    }
                }
            } catch (IllegalArgumentException error) {
                System.out.println("invalid cipherMode in the config:");
                System.out.println(cipherName);
            }

            cipherMode = maybeMode;
        }
    }
}