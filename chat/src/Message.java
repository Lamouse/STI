import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.Key;
import java.security.cert.Certificate;

/**
 * Created by paulo on 22-05-2015.
 */
public class Message implements Serializable{
    private String message = null;
    private Key pubKey = null;
    private SecretKey sKey = null;
    private long timestamp = 0;

    public Message(Key pubKey) {
        this.pubKey = pubKey;
    }

    /*public Message(Certificate ..., SecretKey sKey) {
        this.sKey = sKey;
    }*/

    public Message(String message, long timestamp) {
        this.message = message;
        this.timestamp = timestamp;
    }
}
