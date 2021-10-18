package org.operatorfoundation.shapeshifter.shadow.java;

// CipherMode establishes what algorithm and version you are using.
public enum CipherMode {
    //  AES 196 is not currently supported by go-shadowsocks2.
    //  We are not supporting it at this time either.
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_IETF_POLY1305,
    DarkStar
}
