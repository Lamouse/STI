import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;

/**
 * Created by paulo on 20-05-2015.
 */
public class Teste {

    public static void main(String args[])
    {
        byte[] originalText = null;
        byte[] cipherText = null;
        KeyGenerator kg = null;
        byte[] testdata = "Understanding Java Cryptography".getBytes();
        Cipher myCipher = null;


        // A secret key is used for symmetric encryption/decryption
        try {
            kg = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKey sKey = kg.generateKey();
        System.out.println(sKey.toString());

        // encrypt
        try {
            myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.ENCRYPT_MODE, sKey);
            cipherText = myCipher.doFinal(testdata);

        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }


        // decrypt
        try {
            myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.DECRYPT_MODE, sKey);
            originalText = myCipher.doFinal(cipherText);

            System.out.println("cipher: " + cipherText);
            System.out.println("plain : " + new String(originalText));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }


        // Generate a key-pair
        try {
            Cipher cipher = null;
            cipher = Cipher.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            byte[] cipherText1 = cipher.doFinal(testdata);
            System.out.println("cipher: " + new String(cipherText1));
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] plainText = cipher.doFinal(cipherText1);
            System.out.println("plain : " + new String(plainText));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


    }
}
