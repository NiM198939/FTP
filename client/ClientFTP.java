package client;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.StringTokenizer;

public class ClientFTP {
	String host = null;
	int port = 8889;
	byte[] passwd = null;
	byte[] keypad = new byte[16];
	byte[] hmac = new byte[16];
	byte[] msg = null;
	char lastChar;

	Socket socket = null;
	DataOutputStream dataOuputStream = null;
	DataInputStream dataInputStream = null;
	MessageDigest messageDigest = null;
	InputStreamReader inputReader = null;
	String welcomeMessage = "FTP Server Version 1.0";
	String path = null;

	ClientFTP(String host, int port) {
		inputReader = new InputStreamReader(System.in);
		this.host = host;
		this.port = port;
	}

	boolean verify(byte[] hmac, byte[] msg, byte[] check1) {
		messageDigest.update(msg);
		messageDigest.update(check1);
		byte[] hmac1 = new byte[20];
		hmac1 = messageDigest.digest(passwd);
		return MessageDigest.isEqual(hmac, hmac1);
	}

	
	int receive() throws IOException {
		// HMAC-server(m)=MD5(m+nonce+passwd)
		// Server send: nonce+msg.length+hmac(msg.length)+msg+hmac(msg)
		dataInputStream.readFully(keypad);
		int len = dataInputStream.readInt();
		dataInputStream.readFully(hmac);
		if (!verify(hmac, Integer.toString(len).getBytes(), keypad) || len > 1000000)
			return -1; // hmac failed
		msg = new byte[len];
		dataInputStream.readFully(msg);
		dataInputStream.readFully(hmac);
		if (!verify(hmac, msg, keypad))
			return -1;
		else
			return len;
	}

	void send(byte[] msg) throws IOException {
		// HMAC-client(m)=MD5(m+passwd+nonce)
		// Client send: msg.length+hmac(msg.length)+msg+hmac(msg)
		dataOuputStream.writeInt(msg.length);
		messageDigest.update(Integer.toString(msg.length).getBytes());
		messageDigest.update(passwd);
		hmac = messageDigest.digest(keypad);
		dataOuputStream.write(hmac);
		messageDigest.update(msg);
		messageDigest.update(passwd);
		hmac = messageDigest.digest(keypad);
		dataOuputStream.write(msg);
		dataOuputStream.write(hmac);
		
	}

	void send(String str) throws IOException {
		send(str.getBytes());
	}

	void initiate() {
		try {
			
			System.out.print("Please enter your password:");
			passwd = getPassword(readline() + welcomeMessage);
			System.out.println("Connecting to " + host + "...\n");
			socket = new Socket(host, port);
			dataOuputStream = new DataOutputStream(socket.getOutputStream());
			dataInputStream = new DataInputStream(socket.getInputStream());
			messageDigest = MessageDigest.getInstance("md5");
			path = (new File(".")).getCanonicalPath() + File.separator;

			if (receive() < 0) {
				dataOuputStream.close();
				dataInputStream.close();
				socket.close();
				System.out.println("Server type doesn't match, exit.");
				return;
			}

			System.out.println(new String(msg));
			send("Client Version 1.0");
			if (receive() >= 0) {
				System.out.println(new String(msg));
				String fromUser;
				while (true) {
					System.out.print("SFTP> ");
					fromUser = readline();
					StringTokenizer st = new StringTokenizer(fromUser);
					if (!st.hasMoreTokens())
						continue;
					String command = st.nextToken().toLowerCase();
					if (command.equals("send"))
						put(st);
					else if (command.equals("receive"))
						get(st);
					else if (command.equals("lls"))
						lls(st);
					else if (command.equals("lcd"))
						lcd(st);
					else if (command.equals("bye") || command.equals("quit") || command.equals("close")
							|| command.equals("exit")) {
						send(fromUser); // send command
						break;
					} else { // default response
						send(fromUser); // send command
						if (receive() < 0)
							break;
						System.out.println(new String(msg));
					}
				}
			}
			System.out.println("Thanks for using, bye!");
			dataOuputStream.close();
			dataInputStream.close();
			inputReader.close();
			socket.close();
		} catch (UnknownHostException e) {
			System.out.println("Unknown host: " + host);
			System.exit(-1);
		} catch (Exception e) {
			System.out.println("Error: `.");
			e.printStackTrace();
			System.exit(-1);
		}
	}

	long receiveFile(File file) throws IOException {
			long len;
			dataInputStream.readFully(keypad);
			FileOutputStream fout = new FileOutputStream(file);
			len = dataInputStream.readLong();
			dataInputStream.readFully(hmac);
			if (!verify(hmac, Long.toString(len).getBytes(), keypad)) {
				fout.close();
				return -1;
			}
			byte[] buffer = new byte[4096];
			System.out.println("File " + file.getName() + ": " + len + " bytes");
			int j = 0;
			long startTime = System.currentTimeMillis();
			for (long i = 0; i < len / 4096; i++) {
				dataInputStream.readFully(buffer);
				fout.write(buffer);
				messageDigest.update(buffer);
				for (; j < (1 + i) * 4096 * 50 / len; j++)
					System.out.print(".");
			}
			int restlen = (int) (len % 4096);
			if (restlen > 0) {
				dataInputStream.readFully(buffer, 0, restlen);
				fout.write(buffer, 0, restlen);
				messageDigest.update(buffer, 0, restlen);
			}
			for (; j < 50; j++)
				System.out.print(".");
			long transferTime = System.currentTimeMillis() - startTime;
			long speed;
			if (transferTime > 0)
				speed = len * 1000 / transferTime;
			else
				speed = len;
			double speedK = ((long) (speed * 100 / 1024)) / 100.0;
			double speedM = ((long) (speed * 100 / 1024 / 1024)) / 100.0;
			String speedString;
			if (speedM > 1.0)
				speedString = speedM + " MBytes/S";
			else if (speedK > 1.0)
				speedString = speedK + " KBytes/S";
			else
				speedString = speed + " Bytes/S";
			fout.close();
			System.out.println(" " + transferTime / 1000.0 + " Sec, " + speedString);
			dataInputStream.readFully(hmac);
			messageDigest.update(keypad);
			byte[] hmac1 = messageDigest.digest(passwd);
			if (MessageDigest.isEqual(hmac, hmac1))
			{
				return len;
			}	
			else {
				file.delete();
				
				return -1;
			}
	}
	

	void sendFile(File file) throws IOException {
		
		FileInputStream fin = new FileInputStream(file);
			long len = file.length();
			dataOuputStream.writeLong(len);
			messageDigest.update(Long.toString(len).getBytes());
			messageDigest.update(passwd);
			hmac = messageDigest.digest(keypad);
			dataOuputStream.write(hmac);
			byte[] buffer = new byte[4096];
			System.out.println("File " + file.getName() + ": " + len + " bytes");
			int j = 0;
			long startTime = System.currentTimeMillis();
			for (long i = 0; i < len / 4096; i++) {
				fin.read(buffer);
				dataOuputStream.write(buffer);
				messageDigest.update(buffer);
				for (; j < (1 + i) * 4096 * 50 / len; j++)
					System.out.print(".");
			}
			int restlen = (int) (len % 4096);
			if (restlen > 0) {
				fin.read(buffer, 0, restlen);
				dataOuputStream.write(buffer, 0, restlen);
				messageDigest.update(buffer, 0, restlen);
			}
		
	
			for (; j < 50; j++)
				System.out.print(".");
			long transferTime = System.currentTimeMillis() - startTime;
			long speed;
			if (transferTime > 0)
				speed = len * 1000 / transferTime;
			else
				speed = len;
			double speedK = ((long) (speed * 100 / 1024)) / 100.0;
			double speedM = ((long) (speed * 100 / 1024 / 1024)) / 100.0;
			String speedString;
			if (speedM > 1.0)
				speedString = speedM + " MBytes/S";
			else if (speedK > 1.0)
				speedString = speedK + " KBytes/S";
			else
				speedString = speed + " Bytes/S";
			fin.close();
			System.out.println(" " + transferTime / 1000.0 + " Sec, " + speedString);
			messageDigest.update(passwd);
			hmac = messageDigest.digest(keypad);
			dataOuputStream.write(hmac);

		}
	
	byte[] getPassword(String str){
	try{
	    MessageDigest md=MessageDigest.getInstance("SHA-1");
	    return md.digest(str.getBytes());
    	}catch (NoSuchAlgorithmException e){
	    System.out.println("Hash Function SHA-1 Not Found!");
	    return null;
	}
    }
	void put(StringTokenizer st) throws IOException {
		if (st.countTokens()==0) {
			System.out.println("Error: parameter needed.");
			return;
		}
		while(st.hasMoreTokens())
		{
			
			String name = st.nextToken();
			if (name.startsWith("..") || name.indexOf('\\') >= 0 || name.indexOf('/') >= 0) {
				System.out.println("Error: syntax error");
				continue;
			}
			File tmp = new File(path + name);
			if ((!tmp.isFile()) || (!tmp.canRead())) {
				System.out.println("Error: "+name+" not exist or permission denied.");
				continue;
			}
			send("put " + name);
			if (receive() < 0)
			{
				System.out.println("Error: "+name+" error in sending the command");
				continue;
			}
				
			if (!(new String(msg)).equals("OK")) {
				System.out.println(new String(msg));
				continue;
			}
			int retries = 5;
			while(retries>0)
			{
				sendFile(tmp);
				if (receive() < 0)
				{
					System.out.println("Error: data corrupt");
					System.out.println("Retry "+retries);
					retries = retries - 1;
					continue;
				}
				else
				{
					break;
				}
			}
				
		}
		return;
			
	}

	void get(StringTokenizer st) throws IOException {
		if (st.countTokens()==0) {
			System.out.println("Error: parameter needed.");
			return;
		}
		while(st.hasMoreTokens())
		{
			String name = st.nextToken();
			if (name.startsWith("..") || name.indexOf('\\') >= 0 || name.indexOf('/') >= 0) {
				System.out.println("Error: syntax error");
				continue;
			}
			File tmp = new File(path + name);
			if (tmp.exists()) {
				System.out.println("Error: file exist.");
				continue;
			}
			send("get " + name);
			if (receive() < 0)
			{
				System.out.println("Error: "+name+" error in sending the command");
				continue;
				
			}
				
			if (!(new String(msg)).equals("OK")) {
				System.out.println(new String(msg));
				continue;
			}
			int retries = 5;
			while(retries>0)
			{
				send("Ready");
				if (receiveFile(tmp) < 0)
				{
					System.out.println("Error: data corrupt");
					System.out.println("Retry "+retries);
					retries = retries - 1;
					continue;
				}
				else
				{
					break;
				}
			}
			
				
		}
		return;
	}
	
	 void lls(StringTokenizer st) throws IOException{
	    	File tmp=new File(path);
	    	System.out.println("Local Directory: "+tmp.getCanonicalPath());
	    	String[] fileList=tmp.list();    	
	    	for (int i=0;i<fileList.length;i++) {
	    	    tmp=new File(path+fileList[i]);
	    	    //if (tmp.isDirectory()) msg=msg+"<DIR>\t"+fileList[i]+"\n";
	    	    if (!tmp.isDirectory()) System.out.println(" "+tmp.length()+"\t"+fileList[i]);
	    	    else System.out.println("<DIR>\t"+fileList[i]+File.separator);
	    	}
	    	System.out.println("Total "+fileList.length+" file(s)");
	    }
	    void lcd(StringTokenizer st)throws IOException{
	    	if (!st.hasMoreTokens()){
	    	    System.out.println("Local directory is: "+path);
	    	    return;
	    	}
	    	String path1=st.nextToken();
	    	if (!path1.startsWith(File.separator)) path1=path+path1;
	    	File tmp=new File(path1);
	    	if (tmp.isDirectory()) {
	    		path=tmp.getCanonicalPath();
	    	    if (!path.endsWith(File.separator)) path=path+File.separator;
	    	    System.out.println("Enter local directory: "+path);
	    	}else System.out.println("Operation failed: no such directory");
	    }
	    String readline()throws IOException{
	    	char[] buf=new char[1024];
	    	int i=0;
	 	buf[i]=(char)inputReader.read();
	 	if ((buf[i]=='\n'&&lastChar=='\r')||(buf[i]=='\r'&&lastChar=='\n'))
	 	    buf[i]=(char)inputReader.read();
	    	while(buf[i]!='\n'&&buf[i]!='\r') {
	    	    i++;
	    	    buf[i]=(char)inputReader.read();
	    	}
	    	lastChar=buf[i];
	    	if (i<1) return new String("");
	    	else return new String(buf,0,i);
	    }   

	public static void main(String[] args) throws IOException {
		String host = "localhost";
		int port = 8889;
		if (args.length >= 1) {
			host = args[0];
			if (args.length >= 2)
				port = Integer.parseInt(args[1]);
		}
		(new ClientFTP(host, port)).initiate();
	}
}
