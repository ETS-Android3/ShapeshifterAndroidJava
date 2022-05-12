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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleInstrumentedTest
{
    @Rule
    public Timeout globalTimeout = new Timeout(20 * 1000); // 20 seconds

    @Test
    public void shadowTestMatrixTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
        // TODO: Make sure the password matches the servers public key.
        ShadowConfig config = new ShadowConfig("", "DarkStar");

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
        else if (bytesRead == -1)
        {
            Log.e("ShadowTest", "The test failed, we received EOF instead of the response we expected.");
        }
        else
        {
            Log.e("ShadowTest", "Read 0 bytes");
        }
    }
}