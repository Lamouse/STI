import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import sun.security.x509.BasicConstraintsExtension;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import javax.xml.bind.DatatypeConverter;

//Tested in jdk1.8.0_40
public class Teste2 {

    public static void main(String[] args){
        try{
            //Generate FAKE certificate just to test
            CertAndKeyGen keyGen1=new CertAndKeyGen("RSA","SHA1WithRSA", null);
            keyGen1.generate(1024);
            PrivateKey fakePrivateKey=keyGen1.getPrivateKey();
            X509Certificate fakeCertificate = keyGen1.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);

            fakeCertificate   = createSignedCertificate(fakeCertificate,fakeCertificate,fakePrivateKey);


            //Generate ROOT certificate
            CertAndKeyGen keyGen=new CertAndKeyGen("RSA","SHA1WithRSA", null);
            keyGen.generate(1024);
            PrivateKey rootPrivateKey=keyGen.getPrivateKey();
            X509Certificate rootCertificate = keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long) 365 * 24 * 60 * 60);


            //Generate leaf certificate
            CertAndKeyGen keyGen2=new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen2.generate(1024);
            PrivateKey topPrivateKey=keyGen2.getPrivateKey();
            X509Certificate topCertificate = keyGen2.getSelfCertificate(new X500Name("CN=TOP"), (long) 365 * 24 * 60 * 60);

            rootCertificate   = createSignedCertificate(rootCertificate,rootCertificate,rootPrivateKey);
            topCertificate    = createSignedCertificate(topCertificate,rootCertificate,rootPrivateKey);


            if (topCertificate != null && rootCertificate != null)
            {
                FileOutputStream fout = new FileOutputStream("rootCertificate.ser");
                ObjectOutputStream oos = new ObjectOutputStream(fout);
                oos.writeObject(rootCertificate);
                oos.close();


                fout = new FileOutputStream("rootPrivateKey.ser");
                oos = new ObjectOutputStream(fout);
                oos.writeObject(rootPrivateKey);
                oos.close();

                ////
                // Validate client certificate
                ////

                //Check the chain
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                List mylist = new ArrayList();
                mylist.add(topCertificate);
                CertPath cp = cf.generateCertPath(mylist);

                TrustAnchor anchor = new TrustAnchor(rootCertificate, null);
                PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
                params.setRevocationEnabled(false);

                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                PKIXCertPathValidatorResult pkixCertPathValidatorResult = (PKIXCertPathValidatorResult) cpv.validate(cp, params);

                System.out.println("\n\n\n\n\n\n\n\n\n\n\n" + pkixCertPathValidatorResult);
            }

        }catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static String certToString(X509Certificate cert) {
        StringWriter sw = new StringWriter();
        try {
            // sw.write("-----BEGIN CERTIFICATE-----\n")
            sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
            // sw.write("\n-----END CERTIFICATE-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return sw.toString();
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