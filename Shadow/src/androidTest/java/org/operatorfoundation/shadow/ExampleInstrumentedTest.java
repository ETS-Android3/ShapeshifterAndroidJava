package org.operatorfoundation.shadow;

import static org.junit.Assert.assertNotNull;

import android.util.Log;

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
        ShadowConfig config = new ShadowConfig("9caa4132c724f137c67928e9338c72cfe37e0dd28b298d14d5b5981effa038c9", "DarkStar");

        // TODO: Use an actual server IP and port here:
        ShadowSocket shadowSocket = new ShadowSocket(config, "", 1234);

        assertNotNull(shadowSocket);
        Log.d("ShadowTest", "Initialized a shadowsocket");

        // Write some data.
        String httpRequest = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();

        shadowSocket.getOutputStream().write(textBytes);
        Log.d("ShadowTest", "Wrote some bytes.");

        shadowSocket.getOutputStream().flush();
        Log.d("ShadowTest", "Flushed the output stream.");

        // Read some data.
        byte[] buffer = new byte[235];
        int bytesRead =  shadowSocket.getInputStream().read(buffer);

        if (bytesRead > 0)
        {
            Log.d("ShadowTest", "Read some bytes: " + bytesRead);

            String responseString = new String(buffer, StandardCharsets.UTF_8);
            Log.d("ShadowTest", responseString);

            if (responseString.contains("Yeah!"))
            {
                Log.d("ShadowTest", "The test succeeded!");
            }
            else
            {
                Log.e("ShadowTest", "The test failed, we did not find the response we expected.");
            }
        }
        else
        {
            Log.e("ShadowTest", "Read 0 bytes");
        }
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