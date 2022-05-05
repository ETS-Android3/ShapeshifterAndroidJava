package org.operatorfoundation.shapeshifter.shadow.java;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.google.common.primitives.UnsignedLong;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class ShadowDarkStarCipher extends ShadowCipher {
    SecretKey key;
    UnsignedLong longCounter = UnsignedLong.ZERO;


    // ShadowCipher contains the encryption and decryption methods.
    public ShadowDarkStarCipher(SecretKey key) throws NoSuchAlgorithmException
    {
        this.key = key;

        try
        {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            {
                cipher = Cipher.getInstance("AES_256/GCM/NoPadding");
            }
            else
            {
                cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            }

            saltSize = 32;
        }
        catch (NoSuchPaddingException | NoSuchProviderException e)
        {
            e.printStackTrace();
        }
    }

    // Create a secret key using the two key derivation functions.
    public SecretKey createSecretKey(ShadowConfig config, byte[] salt) throws NoSuchAlgorithmException {
        // FIXME: Actually refactor this function
        //DarkStar.generateSharedKeyClient(config.cipherName, config.password, salt);
        return null;
    }

    // [encrypted payload length][length tag] + [encrypted payload][payload tag]
    // Pack takes the data above and packs them into a singular byte array.
    public byte[] pack(byte[] plaintext) throws Exception {
        // find the length of plaintext
        int plaintextLength = plaintext.length;
        if (plaintextLength > Short.MAX_VALUE) {
            throw new IllegalBlockSizeException();
        }

        // turn the length into two shorts and put them into an array
        // this is encoded in big endian
        short shortPlaintextLength = (short) plaintextLength;
        short leftShort = (short) (shortPlaintextLength / 256);
        short rightShort = (short) (shortPlaintextLength % 256);
        byte leftByte = (byte) (leftShort);
        byte rightByte = (byte) (rightShort);
        byte[] lengthBytes = {leftByte, rightByte};

        // encrypt the length and the payload, adding a tag to each
        byte[] encryptedLengthBytes = encrypt(lengthBytes);
        byte[] encryptedPayload = encrypt(plaintext);

        return Utility.plusEqualsByteArray(encryptedLengthBytes, encryptedPayload);
    }

    // Encrypts the data and increments the nonce counter.
    byte[] encrypt(byte[] plaintext) throws Exception {
        AlgorithmParameterSpec ivSpec;
        byte[] nonce = nonce();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            ivSpec = new GCMParameterSpec(tagSizeBits, nonce);
        } else {
            ivSpec = new AEADParameterSpec(nonce, tagSizeBits);
        }

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        return cipher.doFinal(plaintext);
    }

    // Decrypts data and increments the nonce counter.
    public byte[] decrypt(byte[] encrypted) throws Exception
    {
        AlgorithmParameterSpec ivSpec;
        byte[] nonce = nonce();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        {
            ivSpec = new GCMParameterSpec(tagSizeBits, nonce);
        }
        else
        {
            ivSpec = new AEADParameterSpec(nonce, tagSizeBits);
        }

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(encrypted);
    }

    @Override
    public byte[] nonce() throws Exception {
        // NIST Special Publication 800-38D - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        // Section 8.2.1 - Deterministic Construction
        // Applicable to nonces of 96 bytes or less.

        /*
         In the deterministic construction, the IV is the concatenation of two
         fields, called the fixed field and the invocation field. The fixed field
         shall identify the device, or, more generally, the context for the
         instance of the authenticated encryption function. The invocation field
         shall identify the sets of inputs to the authenticated encryption
         function in that particular device.

         For any given key, no two distinct devices shall share the same fixed
         field, and no two distinct sets of inputs to any single device shall
         share the same invocation field. Compliance with these two requirements
         implies compliance with the uniqueness requirement on IVs in Sec. 8.

         If desired, the fixed field itself may be constructed from two or more
         smaller fields. Moreover, one of those smaller fields could consist of
         bits that are arbitrary (i.e., not necessarily deterministic nor unique
         to the device), as long as the remaining bits ensure that the fixed
         field is not repeated in its entirety for some other device with the
         same key.

         Similarly, the entire fixed field may consist of arbitrary bits when
         there is only one context to identify, such as when a fresh key is
         limited to a single session of a communications protocol. In this case,
         if different participants in the session share a common fixed field,
         then the protocol shall ensure that the invocation fields are distinct
         for distinct data inputs.
        */

        ByteBuffer buffer = ByteBuffer.allocate(12);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) 0x1A);
        buffer.put((byte) 0x1A);
        buffer.put((byte) 0x1A);
        buffer.put((byte) 0x1A);
        /*
         The invocation field typically is either 1) an integer counter or 2) a
         linear feedback shift register that is driven by a primitive polynomial
         to ensure a maximal cycle length. In either case, the invocation field
         increments upon each invocation of the authenticated encryption
         function.

         The lengths and positions of the fixed field and the invocation field
         shall be fixed for each supported IV length for the life of the key. In
         order to promote interoperability for the default IV length of 96 bits,
         this Recommendation suggests, but does not require, that the leading
         (i.e., leftmost) 32 bits of the IV hold the fixed field; and that the
         trailing (i.e., rightmost) 64 bits hold the invocation field.
        */

        buffer.putLong(longCounter.longValue());
        Log.i("nonce", "Nonce created. Counter is " + longCounter);
        System.out.println("key: " + key.getEncoded() + "counter: " + longCounter);
        if (longCounter.compareTo(UnsignedLong.MAX_VALUE) == -1) {  // a < b = -1   a > b = 0
            longCounter = longCounter.plus(UnsignedLong.ONE);
            System.out.println("key: " + key.getEncoded() + "counter: " + longCounter);
        } else {
            throw new Exception("64 bit nonce counter overflow");
        }

        return buffer.array();
    }
}
