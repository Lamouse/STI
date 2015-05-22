import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import java.io.*;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * Created by paulo on 22-05-2015.
 */
public class CreateCertificates {

    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);
        String cname;

        System.out.print("Insert name: ");
        cname=(scanner.nextLine());
        scanner.close();

        System.out.println("Creating new certificate to a client...");

        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(new FileInputStream("rootCertificate.ser"));
            X509Certificate rootCertificate = (X509Certificate) objectInputStream.readObject();

            objectInputStream = new ObjectInputStream(new FileInputStream("rootPrivateKey.ser"));
            PrivateKey rootPrivateKey = (PrivateKey) objectInputStream.readObject();

            //Generate client certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen.generate(1024);
            PrivateKey clientPrivateKey=keyGen.getPrivateKey();
            X509Certificate clientCertificate = keyGen.getSelfCertificate(new X500Name("CN=" + cname), (long) 365 * 24 * 60 * 60);

            clientCertificate = createSignedCertificate(clientCertificate, rootCertificate, rootPrivateKey);

            File client_file = File.createTempFile("client", ".ser");
            FileOutputStream fout = new FileOutputStream(client_file);
            ObjectOutputStream oos = new ObjectOutputStream(fout);
            oos.writeObject(rootCertificate);
            oos.close();

            System.out.println("Certificate created in the following path:\n" + client_file.getAbsoluteFile());
        } catch (Exception e) {
            e.printStackTrace();
        }


        //
    }

    private static X509Certificate createSignedCertificate(X509Certificate cetrificate,X509Certificate issuerCertificate,PrivateKey issuerPrivateKey){
        try{
            Principal issuer = issuerCertificate.getSubjectDN();
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            System.out.println("Algorithm: " + issuerSigAlg);

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            X509CertInfo info = new X509CertInfo(inCertBytes);
            info.set(X509CertInfo.ISSUER, (X500Name) issuer);

            //No need to add the BasicContraint for leaf cert
            if(!cetrificate.getSubjectDN().getName().equals("CN=TOP")){
                CertificateExtensions exts=new CertificateExtensions();
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
                // exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
                info.set(X509CertInfo.EXTENSIONS, exts);
            }

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);

            return outCert;
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return null;
    }
}