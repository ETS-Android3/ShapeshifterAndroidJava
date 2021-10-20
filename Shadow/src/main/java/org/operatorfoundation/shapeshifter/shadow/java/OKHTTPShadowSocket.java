package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.SocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class OKHTTPShadowSocket extends ShadowSocket {

    public OKHTTPShadowSocket(ShadowConfig config, String shadowHost, int shadowPort) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException {
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
