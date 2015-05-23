import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.Key;

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
        this.timestamp = System.currentTimeMillis();
    }

    /*public Message(Certificate ..., SecretKey sKey) {
        this.sKey = sKey;
    }*/

    public Message(String message) {
        this.message = message;
        this.timestamp = System.currentTimeMillis();
    }

    public String getMessage() {
        return message;
    }

    public long getTimestamp() {
        return timestamp;
    }
}
