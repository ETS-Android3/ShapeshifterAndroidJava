package org.operatorfoundation.shadow;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.operatorfoundation.shapeshifter.shadow.java.DarkStar;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocketFactory;
import org.operatorfoundation.shapeshifter.shadow.java.TestServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.TreeSet;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToHex;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToPublicKey;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateClientConfirmationCode;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateECKeys;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateServerConfirmationCode;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateSharedKeyClient;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateSharedKeyServer;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.hexToBytes;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.publicKeyToBytes;

import android.util.Log;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    String clientEphemeralPrivateKeyString = "308193020100301306072A8648CE3D020106082A8648CE3D030107047930770201010420D27CDB0FA88F0FDF05E74AE7D05E50D21E23EE8DE24F18B2B06B031978040777A00A06082A8648CE3D030107A144034200048272A97431C1B78751B5DAF19F7B32ABF7824D8E47101F28BA5543154446969B9334018EBBCB77B2EFFC2A6B6EB2FD87DE5899E04EF8508015610659C84C5C60";
    String clientEphemeralPublicKeyString = "3059301306072A8648CE3D020106082A8648CE3D030107034200048272A97431C1B78751B5DAF19F7B32ABF7824D8E47101F28BA5543154446969B9334018EBBCB77B2EFFC2A6B6EB2FD87DE5899E04EF8508015610659C84C5C60";
    KeyPair clientEphemeralKey = DarkStar.loadECKeys(clientEphemeralPrivateKeyString, clientEphemeralPublicKeyString);

    String serverEphemeralPrivateKeyString = "308193020100301306072A8648CE3D020106082A8648CE3D03010704793077020101042004A7065B1D249C0EDD7D5086A71955D233F04CD210F4AC22DD05264CFC0A001FA00A06082A8648CE3D030107A144034200049B2F18C37AC4176D1545B9E6B740DA755A42E617550AA1DDE67F865F24BED4FC901D93D30E62A400D1A4891878173C20C91B7CE754BB5CE27ABBDD5683D59BE0";
    String serverEphemeralPublicKeyString = "3059301306072A8648CE3D020106082A8648CE3D030107034200049B2F18C37AC4176D1545B9E6B740DA755A42E617550AA1DDE67F865F24BED4FC901D93D30E62A400D1A4891878173C20C91B7CE754BB5CE27ABBDD5683D59BE0";
    KeyPair serverEphemeralKey = DarkStar.loadECKeys(serverEphemeralPrivateKeyString, serverEphemeralPublicKeyString);

    String serverPersistentPrivateKeyString = "308193020100301306072A8648CE3D020106082A8648CE3D03010704793077020101042005B4D9C2C7792964F6E7C01B17701366F83E649C17FB2673F708381970346BA0A00A06082A8648CE3D030107A144034200041FF393BB8D976A5098F4D88853F7EA7A47DF7E1717A7E18084F3E3CA8D0FA9ACFB0F0E18801638712006B041880C0A15D227614E255728FF06EC8B7E466E19D4";
    String serverPersistentPublicKeyString = "3059301306072A8648CE3D020106082A8648CE3D030107034200041FF393BB8D976A5098F4D88853F7EA7A47DF7E1717A7E18084F3E3CA8D0FA9ACFB0F0E18801638712006B041880C0A15D227614E255728FF06EC8B7E466E19D4";
    KeyPair serverPersistentKey = DarkStar.loadECKeys(serverPersistentPrivateKeyString, serverPersistentPublicKeyString);

    byte[] darkStarBytes = "DarkStar".getBytes();
    byte[] clientStringBytes = "client".getBytes();
    byte[] serverStringBytes = "server".getBytes();

    @Test
    public void shadowSocketConstructor1TestAES128() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketConstructor2TestAES128() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        InetAddress address = InetAddress.getByName(null);
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222, address, 0);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketConstructor3TestAES128() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        InetAddress address = InetAddress.getByName("127.0.0.1");
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, address, 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketConstructor4TestAES128() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        InetAddress address = InetAddress.getByName("127.0.0.1");
        InetAddress localAddr = InetAddress.getByName(null);
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, address, 2222, localAddr, 0);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketConstructor5TestAES128() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        SocketAddress socksAddress = new InetSocketAddress("127.0.0.1", 1443);
        Proxy.Type proxyType = Proxy.Type.SOCKS;
        Proxy proxy = new Proxy(proxyType, socksAddress);
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, proxy);
        SocketAddress socketAddress = new InetSocketAddress("127.0.0.1", 2222);
        shadowSocket.connect(socketAddress);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketReadTestAES256() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-256-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void algorythmFinder() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        TreeSet<String> algs = new TreeSet<>();
        for (Provider provider : Security.getProviders()) {
//            provider.getServices().stream()
//                    .filter(s -> "Cipher".equals(s.getType()))
//                    .map(Service::getAlgorithm)
//                    .forEach(algs::add);
            System.out.println(provider.getName());
//            for (java.security.Provider.Service service : provider.getServices()) {
//
//                    System.out.println(service);
//                    System.out.println(service.getType());
//                    System.out.println(service.getAlgorithm());
//            }
        }
        org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames();
        algs.stream().forEach(System.out::println);
    }

    @Test
    public void bouncyCastleTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("CHACHA7539");
        byte[] bytes = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };
        AlgorithmParameterSpec ivSpec = new AEADParameterSpec(bytes, 128);
        byte[] keyBytes = {
                1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2
        };
        SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] plainText = {
                1
        };
        byte[] encrypted = cipher.doFinal(plainText);
    }

    @Test
    public void newKeyParseTest() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] clientEphemeralBytes = DarkStar.publicKeyToBytes(clientEphemeralKey.getPublic());
        PublicKey decodedClientEphemeralKey = DarkStar.bytesToPublicKey(clientEphemeralBytes);
        assertEquals(decodedClientEphemeralKey, clientEphemeralKey.getPublic());

        byte[] serverEphemeralBytes = DarkStar.publicKeyToBytes(serverEphemeralKey.getPublic());
        PublicKey decodedServerEphemeralKey = DarkStar.bytesToPublicKey(serverEphemeralBytes);
        assertEquals(decodedServerEphemeralKey, serverEphemeralKey.getPublic());

        byte[] serverPersistentBytes = DarkStar.publicKeyToBytes(serverPersistentKey.getPublic());
        PublicKey decodedServerPersistentKey = DarkStar.bytesToPublicKey(serverPersistentBytes);
        assertEquals(decodedServerPersistentKey, serverPersistentKey.getPublic());
    }

    @Test
    public void ecdhTest() {
        SecretKey sharedSecret = DarkStar.generateSharedSecret(clientEphemeralKey.getPrivate(), serverPersistentKey.getPublic());
        System.out.println("Format: ");
        System.out.println(sharedSecret.getFormat());
        System.out.println("encoded: ");
        System.out.println(DarkStar.bytesToHex(sharedSecret.getEncoded()));

        assertEquals(sharedSecret.getFormat(), "RAW");
        assertEquals(sharedSecret.getEncoded().length, 32);
    }

    @Test
    public void serverIdentifierTest() throws UnknownHostException {
        byte[] correct = {127, 0, 0, 1, 4, (byte) 210};
        byte[] serverIdentifier = DarkStar.makeServerIdentifier("127.0.0.1", 1234);
        assertArrayEquals(correct, serverIdentifier);
        System.out.println(bytesToHex(serverIdentifier));
    }

    @Test
    public void privateKeyGenTest() {
        KeyPair clientEphemeralKey = generateECKeys();
        PrivateKey clientEphemeralPrivateKey = null;
        clientEphemeralPrivateKey = clientEphemeralKey.getPrivate();
        String format = clientEphemeralPrivateKey.getFormat();
        Log.i("DarkStar", "getFormat result: " + format);
        String encoded = DarkStar.bytesToHex(clientEphemeralPrivateKey.getEncoded(), clientEphemeralPrivateKey.getEncoded().length);
        System.out.println("private: ");
        System.out.println(encoded);
        PublicKey clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        byte[] clientEphemeralKeyData = clientEphemeralPublicKey.getEncoded();
        System.out.println("public: ");
        System.out.println(DarkStar.bytesToHex(clientEphemeralKeyData, clientEphemeralKeyData.length));
        if (!(clientEphemeralPublicKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }
        BCECPublicKey bcecPubKey = (BCECPublicKey) clientEphemeralPublicKey;
        byte[] encodedKey = bcecPubKey.getQ().getEncoded(true);
        System.out.println("public encoded: ");
        System.out.println(DarkStar.bytesToHex(encodedKey, encodedKey.length));
        System.out.println(encodedKey.length);
    }

    @Test
    public void darkStarPublicKeyTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
// generate an ephemeral keypair

        // get the client private and public key
        PublicKey clientEphemeralPublicKey = null;
        if (clientEphemeralKey != null) {
            clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        }

        if (!(clientEphemeralPublicKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }
        BCECPublicKey bcecPubKey = (BCECPublicKey) clientEphemeralPublicKey;
        byte[] encodedKey = bcecPubKey.getQ().getEncoded(true);
        String encodedKeyHex = DarkStar.bytesToHex(encodedKey, encodedKey.length);
        System.out.println(encodedKeyHex);

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint point = ecSpec.getCurve().decodePoint(encodedKey);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECPublicKey myECPublicKey = (ECPublicKey) kf.generatePublic(pubSpec);
        PublicKey decodedPublicKey = (PublicKey) myECPublicKey;

        assertEquals(decodedPublicKey, clientEphemeralPublicKey);
    }

    @Test
    public void sharedKeyGenTest() throws UnknownHostException, NoSuchAlgorithmException {
        SecretKey sharedClientKey = generateSharedKeyClient("127.0.0.1", 1234, clientEphemeralKey, serverEphemeralKey.getPublic(), serverPersistentKey.getPublic());
        SecretKey sharedServerKey = generateSharedKeyServer("127.0.0.1", 1234, serverEphemeralKey, serverPersistentKey, clientEphemeralKey.getPublic());
        assertEquals(sharedClientKey, sharedServerKey);
    }

    @Test
    public void serverConfirmationTest() throws NoSuchAlgorithmException, UnknownHostException, InvalidKeyException {
        SecretKey sharedClientKey = generateSharedKeyClient("127.0.0.1", 1234, clientEphemeralKey, serverEphemeralKey.getPublic(), serverPersistentKey.getPublic());
        SecretKey sharedServerKey = generateSharedKeyServer("127.0.0.1", 1234, serverEphemeralKey, serverPersistentKey, clientEphemeralKey.getPublic());

        byte[] serverSide = generateServerConfirmationCode("127.0.0.1", 1234, serverEphemeralKey.getPublic(), clientEphemeralKey.getPublic(), sharedServerKey);
        byte[] clientSide = generateServerConfirmationCode("127.0.0.1", 1234, serverEphemeralKey.getPublic(), clientEphemeralKey.getPublic(), sharedClientKey);

        assertArrayEquals(serverSide, clientSide);
    }

//    @Test
//    public void clientConfirmationTest() throws NoSuchAlgorithmException, UnknownHostException, InvalidKeyException {
//        byte[] serverSide = generateClientConfirmationCode("127.0.0.1", 1234, serverPersistentKey.getPublic(), clientEphemeralKey.getPublic(), clientEphemeralKey.getPublic(), serverPersistentKey.getPrivate());
//        byte[] clientSide = generateClientConfirmationCode("127.0.0.1", 1234, serverPersistentKey.getPublic(), clientEphemeralKey.getPublic(), serverPersistentKey.getPublic(), clientEphemeralKey.getPrivate());
//
//        assertArrayEquals(serverSide, clientSide);
//    }

    @Test
    public void FunctionalTest() {

    }

    @Test
    public void shadowDarkStarClientTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // generate public key on swift for SPPK
        // pass 1: recent: 03d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6
        // old pass: 3059301306072a8648ce3d020106082a8648ce3d030107034200044ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf3deb2b4df4d7583b521ecd466f37e84b8f7930482ca2a0d18baffd353fb207fd
        ShadowConfig config = new ShadowConfig("d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", "DarkStar");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 1234);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[4];
        shadowSocket.getInputStream().read(buffer);
    }

    @Test
    public void keySizeTest() {
        String publicSwift = "3059301306072a8648ce3d020106082a8648ce3d030107034200044ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf3deb2b4df4d7583b521ecd466f37e84b8f7930482ca2a0d18baffd353fb207fd";
        String privateSwift = "18bdd4600155c7cfb72b6fbde7249184674b2ad874e4b1af60ef7c92dfdfb9b7";

        System.out.println("Java public key size:");
        System.out.println(clientEphemeralPublicKeyString.length());
        System.out.println("Java private key size:");
        System.out.println(clientEphemeralPrivateKeyString.length());
        System.out.println("Swift public key size:");
        System.out.println(publicSwift.length());
        System.out.println("Swift private key size:");
        System.out.println(privateSwift.length());
    }

    @Test
    public void bytesToPublicKeyTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        // get the client private and public key
        PublicKey clientEphemeralPublicKey = null;
        if (clientEphemeralKey != null) {
            clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        }

        if (!(clientEphemeralPublicKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }
        BCECPublicKey bcecPubKey = (BCECPublicKey) clientEphemeralPublicKey;
        byte[] encodedKey = bcecPubKey.getQ().getEncoded(true);
        String encodedKeyHex = DarkStar.bytesToHex(encodedKey, encodedKey.length);
        System.out.println(encodedKeyHex);

        PublicKey decodedKey = DarkStar.bytesToPublicKey(encodedKey);
    }

    @Test
    public void x509LoaderTest() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        byte[] publicKeyBytes = DarkStar.hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200046a8cd9e5f5cfa5118a9d5ebcd7fc9806436ec6731516ff6cfda2f43e1a387a5d3f43586628725e9f7f0d3f1eb1bda463127b52049199bfc7538225df22e9a419");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        X509Certificate cert = X509Certificate.getInstance(publicKeyBytes);

        System.out.println(cert);
        System.out.println(publicKey);
    }

    @Test
    public void compressKeyTest() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        byte[] publicKeyBytes = DarkStar.hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200046a8cd9e5f5cfa5118a9d5ebcd7fc9806436ec6731516ff6cfda2f43e1a387a5d3f43586628725e9f7f0d3f1eb1bda463127b52049199bfc7538225df22e9a419");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
        ECPoint point = bcecPublicKey.getQ();
        byte[] result = point.getEncoded(true);

        System.out.println(result);
    }

    @Test
    public void compressPublicKeyTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String pubkeyString = "4ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf";
        byte[] pubKeyBytes = hexToBytes(pubkeyString);
        PublicKey pubKey = bytesToPublicKey(pubKeyBytes);
        assertNotNull(pubKey);
    }

    @Test
    public void sipTest() throws IOException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        URL url = new URL("https://raw.githubusercontent.com/OperatorFoundation/ShadowSwift/main/Tests/ShadowSwiftTests/testsip008.json");
        UUID uuid = UUID.fromString("27b8a625-4f4b-4428-9f0f-8a2317db7c79");
        ShadowSocketFactory factory = new ShadowSocketFactory(url, uuid);
        factory.createSocket();
    }
}