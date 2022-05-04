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
    public void shadowTestMatrixTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // TODO: Make sure the password matches the servers public key.
        ShadowConfig config = new ShadowConfig("d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", "DarkStar");

        // TODO: Use an actual server IP and port here:
        ShadowSocket shadowSocket = new ShadowSocket(config, "164.92.71.230", 2222);

        assertNotNull(shadowSocket);
        System.out.println("Initialized a shadowsocket");

        // Write some data.
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        System.out.println("Wrote some bytes.");
        shadowSocket.getOutputStream().flush();
        System.out.println("Flushed the output stream.");

        // Read some data.
        byte[] buffer = new byte[4];
        int bytesRead =  shadowSocket.getInputStream().read(buffer);
        System.out.print("Read some bytes: ");
        System.out.println(bytesRead);
        System.out.println("Test Complete!");
    }

    @Test
    public void shadowDarkStarClientTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // Get the users home directory.
        String userHomeDir = System.getProperty("user.home");
        System.out.println("Attempting to find the user home directory: ");
        System.out.println(userHomeDir);

        // Load the server public key from a file.
        // TODO: Load a config file with the key, IP, and Port information instead.
        byte[] serverPersistentPublicKeyBytes = Files.readAllBytes(Paths.get(userHomeDir + "/Desktop/Configs/serverPersistentPublicKey.txt"));
        String serverPersistentPublicKeyString = new String(serverPersistentPublicKeyBytes, StandardCharsets.UTF_8);
        System.out.println(serverPersistentPublicKeyString);
        ShadowConfig config = new ShadowConfig(serverPersistentPublicKeyString, "DarkStar");

        // Create a shadow socket.
        // TODO: Use the config file to get the port and IP information.
        ShadowSocket shadowSocket = new ShadowSocket(config, "164.92.71.230", 2222);
        assertNotNull(shadowSocket);

        // Write some data.
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();

        // Read some data.
        // TODO: Check the received data.
        byte[] buffer = new byte[5];
        shadowSocket.getInputStream().read(buffer);
    }
}