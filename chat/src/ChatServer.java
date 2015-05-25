
import javax.crypto.Cipher;
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


public class ChatServer implements Runnable
{  
	private ChatServerThread clients[]		= new ChatServerThread[20];
	private ServerSocket server_socket		= null;
	private Thread thread					= null;
	private int clientCount					= 0;
	protected KeyPair rsa_key_pair		    = null;
	protected KeyPair sig_key_pair		    = null;
    private String cert_path                = null;
    protected X509Certificate serverCertificate = null;

	public ChatServer(int port) {
		// creating the RSA keys
		try {
			KeyPairGenerator generator = null;
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			rsa_key_pair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// creating the signatures keys
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			sig_key_pair = kpg.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

        // load certificate
        Scanner console = new Scanner(System.in);
        System.out.print("Insert the path of your certificate: ");
        cert_path = console.nextLine();
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(cert_path));
            serverCertificate = (X509Certificate) objectInputStream.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }


        try
      		{  
				// Binds to port and starts server
				System.out.println("Binding to port " + port);
				server_socket = new ServerSocket(port);
				System.out.println("Server started: " + server_socket);
				start();
        	}
      		catch(IOException ioexception)
      		{  
				// Error binding to port
				System.out.println("Binding error (port=" + port + "): " + ioexception.getMessage());
        	}
    	}
    
    	public void run()
    	{  
        	while (!thread.isInterrupted() || thread != null)
        	{  
				try
				{
					// Adds new thread for new client
					System.out.println("Waiting for a client ...");
					addThread(server_socket.accept());
				}
				catch(IOException ioexception)
				{
					System.out.println("Accept error: " + ioexception); stop();
				}
        	}
    	}
    
   	public void start()
    	{  
        	if (thread == null)
        	{  
				// Starts new thread for client
				thread = new Thread(this);
				thread.start();
        	}
    	}
    
    	public void stop()
    	{  
        	if (thread != null)
        	{
				// Stops running thread for client
				thread.interrupt();
				thread = null;
        	}
    	}
   
    	private int findClient(int ID)
    	{  
        	// Returns client from id
        	for (int i = 0; i < clientCount; i++)
				if (clients[i].getID() == ID)
					return i;
        	return -1;
    	}
    
    	public synchronized void handle(int ID, Message msg, SecretKey sKey, PublicKey client_sigKey)
    	{
			msg.decrypteMessage(sKey);
			System.out.println("Check signature:\n" + msg.checkSignatureBytes(client_sigKey));


			String input = msg.getMessage();


			long timestamp = msg.getTimestamp();

			long toleranceTime = 10;
			if ((System.currentTimeMillis() - timestamp) / 1000 > toleranceTime) {
				// Leaving, risk of replicated message
				System.out.println("Detected Risk of replicated message");
				int leaving_id = findClient(ID);
				// Client exits
				clients[leaving_id].send(".quit");
				// Notify remaing users
				for (int i = 0; i < clientCount; i++)
					if (i!=leaving_id)
						clients[i].send("Client " +ID + " exits..");
				remove(ID);
			}

        	if (input.equals(".quit"))
            	{  
                	int leaving_id = findClient(ID);
                	// Client exits
                	clients[leaving_id].send(".quit");
                	// Notify remaing users
                	for (int i = 0; i < clientCount; i++)
                    		if (i!=leaving_id)
                        		clients[i].send("Client " +ID + " exits..");
                	remove(ID);
            	}
        	else
            		// Brodcast message for every other client online
            		for (int i = 0; i < clientCount; i++)
                		clients[i].send(ID + ": " + input);   
    	}
    
    	public synchronized void remove(int ID)
    	{  
        	int pos = findClient(ID);
      
       	 	if (pos >= 0)
        	{  
            		// Removes thread for exiting client
            		ChatServerThread toTerminate = clients[pos];
            		System.out.println("Removing client thread " + ID + " at " + pos);
            		if (pos < clientCount-1)
						System.arraycopy(clients, pos + 1, clients, pos + 1 - 1, clientCount - (pos + 1));
            		clientCount--;

					toTerminate.interrupt();
            		try
            		{  
                		toTerminate.close();
            		}
         
            		catch(IOException ioe)
            		{  
                		System.out.println("Error closing thread: " + ioe); 
            		}
			}
    	}
    
    	private void addThread(Socket socket)
    	{  
    	    	if (clientCount < clients.length)
        	{  
            		// Adds thread for new accepted client
            		System.out.println("Client accepted: " + socket);
            		clients[clientCount] = new ChatServerThread(this, socket);
         
           		try
            		{  
                		clients[clientCount].open();
						clients[clientCount].init_messages();
                		clients[clientCount].start();  
                		clientCount++; 
            		}
            		catch(IOException ioe)
            		{  
               			System.out.println("Error opening thread: " + ioe); 
            		}
       	 	}
        	else
            		System.out.println("Client refused: maximum " + clients.length + " reached.");
    	}
    
    
	public static void main(String args[])
   	{  
        	// ChatServer server = null;
        
        	if (args.length != 1)
				// Displays correct usage for server
				System.out.println("Usage: java ChatServer port");
        	else
				// Calls new server
				new ChatServer(Integer.parseInt(args[0]));
    	}

}

class ChatServerThread extends Thread
{  
    private ChatServer       server    			= null;
    private Socket           socket    			= null;
    private int              ID        			= -1;
    private ObjectInputStream  streamIn  		=  null;
    private ObjectOutputStream streamOut 		= null;
	protected boolean init_msg 					= false;
	private SecretKey secret_key				= null;
	private PublicKey sig_public_key 			= null;

   
    public ChatServerThread(ChatServer _server, Socket _socket)
    {  
        super();
        server = _server;
        socket = _socket;
        ID     = socket.getPort();
    }

	public void init_messages() {
		// send the server public key and the public key to the signature
		try {
			streamOut.writeObject(new Message(server.rsa_key_pair.getPublic(), server.sig_key_pair.getPublic()));
			streamOut.flush();

		    // then received a secret key
			Message msg = (Message) streamIn.readObject();
			secret_key = msg.decrypteSecretMessage(this.server.rsa_key_pair.getPrivate());

		    // then received the certificate and the public key to the signature
            msg = (Message) streamIn.readObject();
            msg.decrypteMessage(secret_key);
            sig_public_key = msg.getPbkey();
            verifyCertificate(msg.getCertificate());

            // finally send his certificate
            streamOut.writeObject(new Message(this.server.serverCertificate, this.server.sig_key_pair.getPublic(), secret_key));

            init_msg = true;
        } catch (Exception e1) {
            e1.printStackTrace();
            this.server.remove(ID);
        }
	}

    public void verifyCertificate(X509Certificate cliente_certificate) throws IOException, ClassNotFoundException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException {
        ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("rootCertificate.ser"));
        X509Certificate rootCertificate = (X509Certificate) objectInputStream.readObject();
        objectInputStream.close();
        objectInputStream = new ObjectInputStream(new FileInputStream("rootPrivateKey.ser"));
        PrivateKey rootPrivateKey = (PrivateKey) objectInputStream.readObject();
        objectInputStream.close();

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
        System.out.println("Client validate with success:\n" + pkixCertPathValidatorResult);


    }

    // Sends message to client
    public void send(String msg)
    {
		if (init_msg) {
			try {
				streamOut.writeObject(new Message(msg, secret_key, this.server.sig_key_pair.getPrivate()));
				streamOut.flush();
			} catch (IOException ioexception) {
				System.out.println(ID + " ERROR sending message: " + ioexception.getMessage());
				server.remove(ID);
				interrupt();
			}
		}
    }

    // Gets id for client
    public int getID()
    {  
        return ID;
    }
   
    // Runs thread
    public void run()
    {  
        System.out.println("Server Thread " + ID + " running.");
      
        while (!isInterrupted())
        {
			try
            {
				server.handle(ID, (Message) streamIn.readObject(), this.secret_key, this.sig_public_key);
            }
         
            catch(IOException ioe)
            {  
                System.out.println(ID + " ERROR reading: " + ioe.getMessage());
                server.remove(ID);
				interrupt();
            } catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
    }
    
    // Opens thread
    public void open() throws IOException
    {
		/*
		streamIn = new ObjectInputStream(new
                        BufferedInputStream(socket.getInputStream()));
        streamOut = new ObjectOutputStream(new
                        BufferedOutputStream(socket.getOutputStream()));
		*/
		streamIn = new ObjectInputStream(socket.getInputStream());
		streamOut = new ObjectOutputStream(socket.getOutputStream());
    }
    
    // Closes thread
    public void close() throws IOException
    {  
        if (socket != null)    socket.close();
        if (streamIn != null)  streamIn.close();
        if (streamOut != null) streamOut.close();
    }
    
}

