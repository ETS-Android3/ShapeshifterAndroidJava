package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;

public class OKHTTPShadowSocket extends ShadowSocket {

    final ShadowConfig shadowConfig;
    final String shadowHost;
    final int shadowPort;

    public OKHTTPShadowSocket(ShadowConfig config, String shadowHost, int shadowPort) throws NoSuchAlgorithmException {
        super(config);

        this.shadowConfig = config;
        this.shadowHost = shadowHost;
        this.shadowPort = shadowPort;
    }

    @Override
    public void connect(SocketAddress endpoint) {

    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) {

    }

    @Override
    public String toString() {
        return "OKHTTPShadowSocket[" + "password = " + shadowConfig.password + ", cipherName = " + shadowConfig.cipherName + "]";
    }
}
