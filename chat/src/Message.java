import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;


public class Message implements Serializable{
    private MSG msg                 = null;
    byte[] msg_data                 = null;
    private byte[] signatureBytes   = null;

    // ñ encriptado
    public Message(PublicKey Key, PublicKey pbkey) {
        this.msg = new MSG(Key, pbkey);
    }

    // encriptado mas n assinado
    public Message(SecretKey sKey, PublicKey rsa_public_key) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, rsa_public_key);
            msg_data = cipher.doFinal(sKey.getEncoded());
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

        msg = null;
    }

    public Message(X509Certificate certificate, PublicKey pbkey, SecretKey sKey) {
        msg = new MSG(certificate, pbkey);

        try {
            Cipher myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.ENCRYPT_MODE, sKey);
            msg_data = myCipher.doFinal(toByteArray(msg));

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

        msg = null;
    }

    // encriptado e assinado
    public Message(String message, SecretKey sKey, PrivateKey privKey) {
        this.msg = new MSG(message);

        setSignatureBytes(privKey);

        try {
            Cipher myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.ENCRYPT_MODE, sKey);
            msg_data = myCipher.doFinal(toByteArray(msg));

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

        msg = null;
    }

    public Message(String message, SecretKey sKey, SecretKey newKey, PrivateKey privKey) {
        this.msg = new MSG(message, newKey);
        setSignatureBytes(privKey);

        try {
            Cipher myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.ENCRYPT_MODE, sKey);
            msg_data = myCipher.doFinal(toByteArray(msg));

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

        msg = null;
    }


    private byte[] toByteArray(MSG msg) {
        byte[] data = null;
        ByteArrayOutputStream bos = null;
        ObjectOutputStream oos = null;
        try {
            bos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(bos);
            oos.writeObject(msg);
            oos.flush();
            data = bos.toByteArray();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return data;
    }

    private Object toObject(byte[] bytes) {
        Object obj = null;
        ByteArrayInputStream bis = null;
        ObjectInputStream ois = null;
        try {
            bis = new ByteArrayInputStream(bytes);
            ois = new ObjectInputStream(bis);
            obj = ois.readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (ois != null) {
                try {
                    ois.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return obj;
    }

    public void setSignatureBytes(PrivateKey privKey) {
        byte[] data;
        ByteArrayOutputStream bos = null;
        ObjectOutputStream oos = null;
        try {
            bos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(bos);
            oos.writeObject(this.msg);
            oos.flush();
            data = bos.toByteArray();

            Signature sig = Signature.getInstance("MD5WithRSA");
            sig.initSign(privKey);
            sig.update(data);
            this.signatureBytes = sig.sign();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public boolean checkSignatureBytes(PublicKey publKey) {
        byte[] data;
        ByteArrayOutputStream bos = null;
        ObjectOutputStream oos = null;
        try {
            bos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(bos);
            oos.writeObject(this.msg);
            oos.flush();
            data = bos.toByteArray();

            Signature sig = Signature.getInstance("MD5WithRSA");
            sig.initVerify(publKey);
            sig.update(data);
            return sig.verify(this.signatureBytes);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return false;
    }

    public SecretKey decrypteSecretMessage(PrivateKey rsa_private_key) {
        Cipher myCipher;
        SecretKey key = null;
        try {
            myCipher = Cipher.getInstance("RSA");
            myCipher.init(Cipher.DECRYPT_MODE, rsa_private_key);
            byte[] data = myCipher.doFinal(msg_data);
            key = new SecretKeySpec(data, 0, data.length, "DES");
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
        return key;
    }

    public void decrypteMessage(SecretKey sKey) {
        Cipher myCipher;
        try {
            myCipher = Cipher.getInstance("DES");
            myCipher.init(Cipher.DECRYPT_MODE, sKey);
            msg = (MSG) toObject(myCipher.doFinal(msg_data));
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

    public String getMessage() {
        return this.msg.message;
    }

    public long getTimestamp() {
        return this.msg.timestamp;
    }

    public SecretKey getsKey() {
        return this.msg.sKey;
    }

    public X509Certificate getCertificate() {
        return this.msg.certificate;
    }

    public PublicKey getPbkey() {
        return this.msg.pbkey;
    }

    public PublicKey getKey() {
        return this.msg.key;
    }
}

class MSG implements Serializable{
    public String message              = null;
    public SecretKey sKey              = null;
    public long timestamp              = 0;
    public X509Certificate certificate = null;
    public PublicKey pbkey             = null;
    public PublicKey key               = null;

    public MSG(SecretKey sKey) {
        this.sKey = sKey;
        this.timestamp = System.currentTimeMillis();
    }

    public MSG(PublicKey Key, PublicKey pbkey) {
        this.key = Key;
        this.pbkey = pbkey;
        this.timestamp = System.currentTimeMillis();
    }

    public MSG(X509Certificate certificate, PublicKey pbkey) {
        this.certificate = certificate;
        this.pbkey = pbkey;
        this.timestamp = System.currentTimeMillis();
    }

    public MSG(String message) {
        this.message = message;
        this.timestamp = System.currentTimeMillis();
    }

    public MSG(String message, SecretKey newKey) {
        this.message = message;
        this.sKey = newKey;
        this.timestamp = System.currentTimeMillis();
    }
}