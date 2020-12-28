package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;

public class OKHTTPShadowSocket extends ShadowSocket {

    public OKHTTPShadowSocket(ShadowConfig config, String shadowHost, int shadowPort) throws NoSuchAlgorithmException, IOException {
        super(config, shadowHost, shadowPort);
    }

    @Override
    public void connect(SocketAddress endpoint) {

    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) {

    }

    @Override
    public String toString() {
        return "";
    }
}
