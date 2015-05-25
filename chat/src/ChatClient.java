
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;


public class ChatClient implements Runnable
{  
    private Socket socket              = null;
    protected Thread thread            = null;
    private Scanner console            = null;
    protected ObjectOutputStream streamOut = null;
    private ChatClientThread client    = null;
    protected SecretKey sKey           = null;
    protected PublicKey server_pubKey  = null;
    protected PublicKey server_sigKey  = null;
    protected KeyPair client_sigKey    = null;
    protected String cert_path         = null;

    public ChatClient(String serverName, int serverPort)
    {
        // creating keys to the signature
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            client_sigKey = kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        System.out.println("Establishing connection to server...");
        
        try
        {
            // Establishes connection with server (name and port)
            socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server: " + socket);
            start();
        }
        
        catch(UnknownHostException uhe)
        {  
            // Host unkwnown
            System.out.println("Error establishing connection - host unknown: " + uhe.getMessage()); 
        }
      
        catch(IOException ioexception)
        {  
            // Other error establishing connection
            System.out.println("Error establishing connection - unexpected exception: " + ioexception.getMessage()); 
        }
        
   }
    
   public void run()
   {
       while (thread != null)
       {

           try
           {
               // Sends message from console to server
               streamOut.writeObject(new Message(console.nextLine(), sKey, client_sigKey.getPrivate()));
               streamOut.flush();
           }
         
           catch(IOException ioexception)
           {
               if(thread != null) {
                   System.out.println("Error sending string to server: " + ioexception.getMessage());
                   stop();
               }
           }
       }
    }
    
    public void handle(Message msg_class)
    {
        msg_class.decrypteMessage(sKey);
        String msg = msg_class.getMessage();

        // System.out.println("Check signature of server: " + msg_class.checkSignatureBytes(this.server_sigKey));

        long timestamp = msg_class.getTimestamp();

        long toleranceTime = 10;
        if ((System.currentTimeMillis() - timestamp) / 1000 > toleranceTime) {
            // Leaving, risk of replicated message
            System.out.println("Detected Risk of replicated message\nExiting...Please press RETURN to exit ...");
            stop();
        }
        else if(!msg_class.checkSignatureBytes(this.server_sigKey)) {
            System.out.println("Integrity of message does not verified\nExiting...Please press RETURN to exit ...");
            stop();
        }

        // Receives message from server
        if (msg.equals(".quit"))
        {  
            // Leaving, quit command
            System.out.println("Exiting...Please press RETURN to exit ...");
            stop();
        }
        else
            // else, writes message received from server to console
            System.out.println(msg);
    }
    
    // Inits new client thread
    public void start() throws IOException
    {  
        console   = new Scanner(System.in);
        streamOut = new ObjectOutputStream(socket.getOutputStream());

        System.out.print("Insert the path of your certificate: ");
        cert_path = console.nextLine();

        if (thread == null)
        {
            client = new ChatClientThread(this, socket);
            thread = new Thread(this);
        }
    }
    
    // Stops client thread
    public void stop()
    {
        if(thread != null) {
            thread.interrupt();
            thread = null;
        }
        try
        {
            if (console   != null)  console.close();
            if (streamOut != null)  streamOut.close();
            if (socket    != null)  socket.close();
        }
        catch(IOException ioe) {
            System.out.println("Error closing thread..."); }
        client.close();
        client.interrupt();
    }
   
    
    public static void main(String args[])
    {
        if (args.length != 2)
            // Displays correct usage syntax on stdout
            System.out.println("Usage: java ChatClient host port");
        else
            // Calls new client
            new ChatClient(args[0], Integer.parseInt(args[1]));
    }
    
}

class ChatClientThread extends Thread
{  
    private Socket           socket   = null;
    private ChatClient       client   = null;
    private ObjectInputStream  streamIn = null;

    public ChatClientThread(ChatClient _client, Socket _socket)
    {  
        client   = _client;
        socket   = _socket;
        open();
        start();
    }
   
    public void open()
    {  
        try
        {
            streamIn  = new ObjectInputStream(socket.getInputStream());
        }
        catch(IOException ioe)
        {  
            System.out.println("Error getting input stream: " + ioe);
            client.stop();
        }
    }
    
    public void close()
    {  
        try
        {  
            if (streamIn != null) streamIn.close();
        }
      
        catch(IOException ioe)
        {  
            System.out.println("Error closing input stream: " + ioe);
        }
    }
    
    public void run()
    {
        init_messages();

        while (!isInterrupted())
        {   try
            {  
                client.handle((Message) streamIn.readObject());
            }
            catch(IOException ioe)
            {  
                System.out.println("Listening error: " + ioe.getMessage());
                client.stop();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    public void init_messages() {
        // received the server public key and the public key to the signature
        try {
            Message msg = (Message) streamIn.readObject();
            this.client.server_pubKey = msg.getKey();
            this.client.server_sigKey = msg.getPbkey();

            // first send a secret key
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            this.client.sKey = kg.generateKey();
            this.client.streamOut.writeObject(new Message(this.client.sKey, this.client.server_pubKey));
            this.client.streamOut.flush();

            // then send the certificate and the public key to the signature
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(this.client.cert_path));
            X509Certificate clienteCertificate = (X509Certificate) objectInputStream.readObject();
            this.client.streamOut.writeObject(new Message(clienteCertificate, this.client.client_sigKey.getPublic(), this.client.sKey));
            objectInputStream.close();

            // finally received the certificate from the server
            msg = (Message) streamIn.readObject();
            msg.decrypteMessage(this.client.sKey);
            verifyCertificate(msg.getCertificate());
        }catch (Exception e1){
            e1.printStackTrace();
            client.stop();
            return;
        }

        this.client.thread.start();
    }

    public void verifyCertificate(X509Certificate cliente_certificate) throws IOException, ClassNotFoundException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("rootCertificate.ser"));
        X509Certificate rootCertificate = (X509Certificate) objectInputStream.readObject();
        objectInputStream.close();
        // objectInputStream = new ObjectInputStream(new FileInputStream("rootPrivateKey.ser"));
        // PrivateKey rootPrivateKey = (PrivateKey) objectInputStream.readObject();
        // objectInputStream.close();

        //Check the chain
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List mylist = new ArrayList();
        mylist.add(cliente_certificate);
        CertPath cp = cf.generateCertPath(mylist);

        TrustAnchor anchor = new TrustAnchor(rootCertificate, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        PKIXCertPathValidatorResult pkixCertPathValidatorResult = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
        System.out.println("Server validate with success:\n" + pkixCertPathValidatorResult);
    }
}

