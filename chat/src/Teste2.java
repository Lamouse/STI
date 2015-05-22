import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;

/**
 * Created by paulo on 21-05-2015.
 */


public class Teste2 {
    public static void main(String[] a) {
        if (a.length<3) {
            System.out.println("Usage:");
            System.out.println("java JcaKeyStoreTest store sPass alias");
            return;
        }
        String store = a[0];
        String sPass = a[1];
        String alias = a[2];
        try {
            test(store,sPass,alias);
        } catch (Exception e) {
            System.out.println("Exception: "+e);
            return;
        }
    }
    private static void test(String store, String sPass, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        System.out.println();
        System.out.println("KeyStore Object Info: ");
        System.out.println("Type = " + ks.getType());
        System.out.println("Provider = " + ks.getProvider());
        System.out.println("toString = " + ks.toString());

        FileInputStream fis = new FileInputStream(store);
        ks.load(fis, sPass.toCharArray());
        fis.close();
        System.out.println();
        System.out.println("KeyStore Content: ");
        System.out.println("Size = " + ks.size());
        Enumeration e = ks.aliases();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            System.out.print("   " + name + ": ");
            if (ks.isKeyEntry(name)) System.out.println(" Key entry");
            else System.out.println(" Certificate entry");
        }

        java.security.cert.Certificate cert = ks.getCertificate(alias);
        System.out.println();
        System.out.println("Certificate Object Info: ");
        System.out.println("Type = " + cert.getType());
        System.out.println("toString = " + cert.toString());

        FileOutputStream fos = new FileOutputStream(alias + ".crt");
        byte[] certBytes = cert.getEncoded();
        fos.write(certBytes);
        fos.close();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        System.out.println();
        System.out.println("CertificateFactory Object Info: ");
        System.out.println("Type = " + cf.getType());
        System.out.println("Provider = " + cf.getProvider());
        System.out.println("toString = " + cf.toString());

        fis = new FileInputStream(alias + ".crt");
        cert = cf.generateCertificate(fis);
        ks.setCertificateEntry(alias + ks.size(), cert);
        fis.close();

        fos = new FileOutputStream(store);
        ks.store(fos, sPass.toCharArray());
        fos.close();
    }
}
