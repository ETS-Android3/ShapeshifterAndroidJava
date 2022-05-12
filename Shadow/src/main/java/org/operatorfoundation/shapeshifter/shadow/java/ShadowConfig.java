package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

public class ShadowConfig {
    final String password;
    final String cipherName;
    public CipherMode cipherMode;

    // ShadowConfig is a class that implements the arguments necessary for a Shadowsocks connection.
    public ShadowConfig(String password, String cipherName) throws IllegalArgumentException
    {
        this.password = password;
        this.cipherName = cipherName;

        try
        {
            cipherMode = CipherMode.valueOf(cipherName.toLowerCase());
        }
        catch (IllegalArgumentException error)
        {
            Log.e("ShadowConfig", "Invalid cipherMode in the config: $cipherName");
            throw error;
        }
    }
}