package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.*;


public class DarkStar {
    public static byte[] iv = new SecureRandom().generateSeed(16);
    public static int P256KeySize = 32;
    public static int ConfirmationSize = 32;
    public SecretKey sharedKeyClient;
    public SecretKey decryptKey;
    static byte[] darkStarBytes = "DarkStar".getBytes();
    static byte[] clientStringBytes = "client".getBytes();
    static byte[] serverStringBytes = "server".getBytes();
    KeyPair clientEphemeralKeyPair;
    PublicKey serverPersistentPublicKey;
    byte[] clientNonce;
    byte[] serverNonce;
    ShadowConfig config;
    String host;
    int port;

    public DarkStar(ShadowConfig config, String host, int port) {
        this.config = config;
        this.host = host;
        this.port = port;
    }

    public byte[] createSalt() throws NoSuchAlgorithmException, InvalidKeySpecException, UnknownHostException, NoSuchProviderException {
        // take ServerPersistentPublicKey out of password string
        byte[] serverPersistentPublicKeyData = hexToBytes(config.password);
        this.serverPersistentPublicKey = bytesToPublicKey(serverPersistentPublicKeyData);

        // generate an ephemeral keypair
        this.clientEphemeralKeyPair = generateECKeys();

        // get the client private and public key
        PrivateKey clientEphemeralPrivateKey = null;
        PublicKey clientEphemeralPublicKey = null;
        if (clientEphemeralKeyPair != null) {
            clientEphemeralPrivateKey = clientEphemeralKeyPair.getPrivate();
            clientEphemeralPublicKey = clientEphemeralKeyPair.getPublic();
        }

        // convert the public key into data to be sent to the server
        byte[] clientEphemeralPublicKeyData = publicKeyToBytes(clientEphemeralPublicKey);
        byte[] salt = clientEphemeralPublicKeyData;

        // Generate client confirmation code
        byte[] clientConfirmationCode = generateClientConfirmationCode(host, port, serverPersistentPublicKey, clientEphemeralPublicKey, clientEphemeralPrivateKey);
        salt = Utility.plusEqualsByteArray(salt, clientConfirmationCode);

        // Create the nonce
        clientNonce = generateNonce();
        salt = Utility.plusEqualsByteArray(salt, clientNonce);

        System.out.println("salt: " + bytesToHex(salt));

        return salt;
    }

    public void splitSalt(byte[] salt, byte[] ephemeralPublicKeyBuf, byte[] confirmationCodeBuf, byte[] nonceBuf)  {
        if (salt.length != 155) {
            Log.e("DarkStar", "incorrect salt size")            ;
        }

        System.arraycopy(salt, 0, ephemeralPublicKeyBuf, 0, 32);
        System.arraycopy(salt, 32, confirmationCodeBuf, 0, 32);
        System.arraycopy(salt, 64 , nonceBuf, 0, 32);
    }

    public ShadowCipher makeDecryptionCipher(byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException, UnknownHostException, InvalidKeyException {

        byte[] serverEphemeralPublicKeyData = new byte[32];
        byte[] serverConfirmationCode = new byte[32];
        byte[] serverNonce = new byte[32];

        splitSalt(salt, serverEphemeralPublicKeyData, serverConfirmationCode, serverNonce);

        // turn the server's public key data back to a public key type
        PublicKey serverEphemeralPublicKey = bytesToPublicKey(serverEphemeralPublicKeyData);

        // derive shared keys
        sharedKeyClient = generateSharedKeyClient(host, port, clientEphemeralKeyPair, serverEphemeralPublicKey, serverPersistentPublicKey);

        // check confirmationCode
        byte[] clientCopyServerConfirmationCode = generateServerConfirmationCode(host, port, serverEphemeralPublicKey, clientEphemeralKeyPair.getPublic(), sharedKeyClient);
        if (!Arrays.equals(clientCopyServerConfirmationCode, serverConfirmationCode)) {
            throw new InvalidKeyException();
        }

        return new ShadowDarkStarCipher(sharedKeyClient, serverNonce);
    }

    public ShadowCipher makeEncryptionCipher() throws NoSuchAlgorithmException {
        return new ShadowDarkStarCipher(sharedKeyClient, clientNonce);
    }

    public static KeyPair generateECKeys() {
        try {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    "EC", new BouncyCastleProvider());

            keyPairGenerator.initialize(parameterSpec);

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static KeyPair loadECKeys(String privateKeyString, String publicKeyString) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());

            byte[] privateKeyBytes = hexToBytes(privateKeyString);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(spec);

            byte[] publicKeyBytes = hexToBytes(publicKeyString);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("secp256r1");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    // function used for testing only
    public static SecretKey generateSharedKeyServer(String host, int port, KeyPair serverEphemeral, KeyPair serverPersistent, PublicKey clientEphemeralPublicKey) throws UnknownHostException, NoSuchAlgorithmException {
        SecretKey ecdh1 = DarkStar.generateSharedSecret(serverEphemeral.getPrivate(), clientEphemeralPublicKey);
        SecretKey ecdh2 = DarkStar.generateSharedSecret(serverPersistent.getPrivate(), clientEphemeralPublicKey);
        byte[] serverIdentifier = DarkStar.makeServerIdentifier(host, port);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(ecdh1.getEncoded());
        digest.update(ecdh2.getEncoded());
        digest.update(serverIdentifier);
        digest.update(publicKeyToBytes(clientEphemeralPublicKey));
        digest.update(publicKeyToBytes(serverEphemeral.getPublic()));
        digest.update(darkStarBytes);
        byte[] result = digest.digest();

        return new SecretKeySpec(result, 0, result.length, "AES");
    }

    public static SecretKey generateSharedKeyClient(String host, int port, KeyPair clientEphemeral, PublicKey serverEphemeralPublicKey, PublicKey serverPersistentPublicKey) throws UnknownHostException, NoSuchAlgorithmException {
        SecretKey ecdh1 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverEphemeralPublicKey);
        SecretKey ecdh2 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverPersistentPublicKey);
        byte[] serverIdentifier = DarkStar.makeServerIdentifier(host, port);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        System.out.println("ecdh1: " + bytesToHex(ecdh1.getEncoded()));
        System.out.println("ecdh2: " + bytesToHex(ecdh2.getEncoded()));
        System.out.println("SEPub: " + bytesToHex(publicKeyToBytes(serverEphemeralPublicKey)));

        digest.update(ecdh1.getEncoded());
        digest.update(ecdh2.getEncoded());
        digest.update(serverIdentifier);
        digest.update(publicKeyToBytes(clientEphemeral.getPublic()));
        digest.update(publicKeyToBytes(serverEphemeralPublicKey));
        digest.update(darkStarBytes);
        byte[] result = digest.digest();

        return new SecretKeySpec(result, 0, result.length, "AES");
    }

    public static byte[] makeServerIdentifier(String host, int port) throws UnknownHostException {
        InetAddress ip = InetAddress.getByName(host);
        byte[] address = ip.getAddress();
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.putShort((short) port);
        byte[] portBytes = buf.array();

        return Utility.plusEqualsByteArray(address, portBytes);
    }

    public static byte[] generateServerConfirmationCode(String host, int port, PublicKey serverEphemeralPublicKey, PublicKey clientEphemeralPublicKey, SecretKey sharedKey) throws NoSuchAlgorithmException, UnknownHostException, InvalidKeyException {
        byte[] secretKeyData = sharedKey.getEncoded();
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverEphemeralPublicKeyData = serverEphemeralPublicKey.getEncoded();
        byte[] clientEphemeralPublicKeyData = clientEphemeralPublicKey.getEncoded();

        System.out.println("SCC1: " + bytesToHex(secretKeyData));
        System.out.println("SCC2: " + bytesToHex(serverIdentifier));
        System.out.println("SCC3: " + bytesToHex(serverEphemeralPublicKeyData));
        System.out.println("SCC4: " + bytesToHex(clientEphemeralPublicKeyData));

        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyData, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        mac.update(serverIdentifier);
        mac.update(serverEphemeralPublicKeyData);
        mac.update(clientEphemeralPublicKeyData);
        mac.update(darkStarBytes);
        mac.update(serverStringBytes);

        return mac.doFinal();
    }

    public static byte[] generateClientConfirmationCode(String host, int port, PublicKey serverPersistentPublicKey, PublicKey clientEphemeralPublicKey, PrivateKey clientEphemeralPrivateKey) throws NoSuchAlgorithmException, UnknownHostException {
        SecretKey sharedSecret = DarkStar.generateSharedSecret(clientEphemeralPrivateKey, serverPersistentPublicKey);
        System.out.println("SPP: " + bytesToHex(serverPersistentPublicKey.getEncoded()));
        System.out.println("CEPub: " + bytesToHex(clientEphemeralPublicKey.getEncoded()));
        System.out.println("CEPriv: " + bytesToHex(clientEphemeralPrivateKey.getEncoded()));
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverPersistentPublicKeyData = serverPersistentPublicKey.getEncoded();
        byte[] clientEphemeralPublicKeyData = clientEphemeralPublicKey.getEncoded();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        System.out.println("ecdhData: " + bytesToHex(sharedSecret.getEncoded()));
        System.out.println("serverIdentifier: " + bytesToHex(serverIdentifier));
        System.out.println("SPPK: " + bytesToHex(serverPersistentPublicKeyData));
        System.out.println("CEPK: " + bytesToHex(clientEphemeralPublicKeyData));

        digest.update(sharedSecret.getEncoded());
        digest.update(serverIdentifier);
        digest.update(serverPersistentPublicKeyData);
        digest.update(clientEphemeralPublicKeyData);
        digest.update(darkStarBytes);
        digest.update(clientStringBytes);

        return digest.digest();
    }

    public byte[] generateNonce() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom random = SecureRandom.getInstance("NativePRNG", "SUN");
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] publicKeyToBytes(PublicKey pubKey) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) pubKey;
        ECPoint point = bcecPublicKey.getQ();
        byte[] encodedPoint = point.getEncoded(true);
        byte[] result = new byte[32];
        System.arraycopy(encodedPoint, 1, result, 0, 32);
        return result;
    }

    public static PublicKey bytesToPublicKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
//        ECPoint point = ecSpec.getCurve().decodePoint(bytes);
//        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
//        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
//        return kf.generatePublic(pubSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        byte[] encodedPoint = new byte[33];
        System.arraycopy(bytes, 0, encodedPoint, 1, 32);
        encodedPoint[0] = 3;
        ECPoint point = ecSpec.getCurve().decodePoint(encodedPoint);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        return keyFactory.generatePublic(pubSpec);
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }
}