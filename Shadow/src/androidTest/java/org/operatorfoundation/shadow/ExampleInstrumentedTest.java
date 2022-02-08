package org.operatorfoundation.shadow;

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleInstrumentedTest {

    @Rule
    public Timeout globalTimeout = new Timeout(20 * 1000); // 20 seconds

    @Test
    public void shadowDarkStarServerTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        ShadowConfig config = new ShadowConfig("3059301306072A8648CE3D020106082A8648CE3D030107034200041FF393BB8D976A5098F4D88853F7EA7A47DF7E1717A7E18084F3E3CA8D0FA9ACFB0F0E18801638712006B041880C0A15D227614E255728FF06EC8B7E466E19D4", "DarkStar");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 1234);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[5];
        shadowSocket.getInputStream().read(buffer);
    }
}