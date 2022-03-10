package org.operatorfoundation.shadow;

import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.operatorfoundation.shapeshifter.shadow.java.Bloom;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
    public void shadowDarkStarClientTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        String userHomeDir = System.getProperty("user.home");
        Bloom bloom = new Bloom();
        bloom.load(userHomeDir + "/Desktop/Configs/bloom.txt");
        byte[] serverPersistentPublicKeyBytes = Files.readAllBytes(Paths.get(userHomeDir + "/Desktop/Configs/serverPersistentPublicKey.txt"));
        String serverPersistentPublicKeyString = new String(serverPersistentPublicKeyBytes, StandardCharsets.UTF_8);
        System.out.println(serverPersistentPublicKeyString);
        ShadowConfig config = new ShadowConfig(serverPersistentPublicKeyString, "DarkStar");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 1234);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[5];
        shadowSocket.getInputStream().read(buffer);
        bloom.save(userHomeDir + "/Desktop/Configs/bloom.txt");
    }
}