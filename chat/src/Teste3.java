import sun.misc.BASE64Encoder;

import java.io.UnsupportedEncodingException;
import java.security.*;

public class Teste3 {
    public static void main(String args[]) {
        KeyPairGenerator kpg = null;
        String testedString = "test";
        try {

            // create a signature
            byte[] data = testedString.getBytes("UTF8");
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair keyPair = kpg.genKeyPair();
            Signature sig = Signature.getInstance("MD5WithRSA");
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            System.out.println("Singature:" + new BASE64Encoder().encode(signatureBytes));

            // verify signature
            sig.initVerify(keyPair.getPublic());
            sig.update(data);

            System.out.println(sig.verify(signatureBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }
}