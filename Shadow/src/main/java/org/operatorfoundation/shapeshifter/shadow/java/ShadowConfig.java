package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

public class ShadowConfig {
    final String password;
    final String cipherName;
    public CipherMode cipherMode;

    // ShadowConfig is a class that implements the arguments necessary for a Shadowsocks connection.
    public ShadowConfig(String password, String cipherName) throws IllegalArgumentException {
        this.password = password;
        this.cipherName = cipherName;

        CipherMode maybeMode = null;

        switch (cipherName) {
            case "AES-128-GCM":
                maybeMode = CipherMode.AES_128_GCM;
                break;

            case "AES-256-GCM":
                maybeMode = CipherMode.AES_256_GCM;
                break;

            case "CHACHA20-IETF-POLY1305":
                maybeMode = CipherMode.CHACHA20_IETF_POLY1305;
                break;

        }

        if (maybeMode == null) {
            Log.e("ShadowConfig", "Invalid cipherMode in the config: $cipherName");
            throw new IllegalArgumentException();
        }

        cipherMode = maybeMode;

    }
}