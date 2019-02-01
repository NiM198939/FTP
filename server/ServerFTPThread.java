package server;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.StringTokenizer;


import java.io.*;
import java.net.*;

public class ServerFTPThread extends Thread {
	ServerSocket FTPServerSocket;
	Socket clientSocket;
	Socket connection = null;
	DataOutputStream outputStreamString;
	DataInputStream inputStreamString;
	MessageDigest messageDigest;
	String filename = "";
	String contents = "";
	String cwd = "";
	String home = "";
	
	byte[] welcomeMessage;
	byte[] keypad = null;
	byte[] passwd = null;
	byte[] hmac = new byte[16];
	byte[] message = null;
	
	File file = null;

	ServerFTPThread(Socket socket, String pass, String welcomeMessage, String root) {
		this.clientSocket = socket;
		this.welcomeMessage = welcomeMessage.getBytes();
		this.home = root;
		this.cwd = File.separator;
		this.keypad = this.welcomeMessage;
		this.passwd = getPassword(pass + welcomeMessage);
	}

	byte[] getPassword(String str) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			return md.digest(str.getBytes());
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Hash Function SHA-1 Not Found!");
			return null;
		}
	}

	byte[] getNewKeypad() {
		messageDigest.update(keypad);
		messageDigest.update(passwd);
		return messageDigest.digest(((new Date()).toString()).getBytes());
	}

	void send(byte[] msg) throws IOException {
		// HMAC-server(m)=MD5(m+keypad+passwd)
		// Server send: nonce+msg.length+hmac(msg.length)+msg+hmac(msg)
		keypad = getNewKeypad();
		outputStreamString.write(keypad);
		outputStreamString.writeInt(msg.length);
		messageDigest.update(Integer.toString(msg.length).getBytes());
		messageDigest.update(keypad);
		hmac = messageDigest.digest(passwd);
		outputStreamString.write(hmac);
		messageDigest.update(msg);
		messageDigest.update(keypad);
		hmac = messageDigest.digest(passwd);
		outputStreamString.write(msg);
		outputStreamString.write(hmac);
	}

	void send(String str) throws IOException {
		send(str.getBytes());
	}

	int receive() throws IOException {
		// HMAC-client(m)=MD5(m+passwd+keypad)
		// Client send: msg.length+hmac(msg.length)+msg+hmac(msg)
		int len = inputStreamString.readInt();
		inputStreamString.readFully(hmac);
		if (!verify(hmac, Integer.toString(len).getBytes(), keypad) || len > 1000000)
			return -1; // hmac failed
		message = new byte[len];
		inputStreamString.readFully(message);
		inputStreamString.readFully(hmac);
		if (!verify(hmac, message, keypad))
			return -1;
		else
			return len;
	}

	boolean verify(byte[] hmac, byte[] msg, byte[] keypad) {
		messageDigest.update(msg);
		messageDigest.update(passwd);
		byte[] hmac1 = messageDigest.digest(keypad);
		return MessageDigest.isEqual(hmac, hmac1);
	}

	public void run() {
		try {
			outputStreamString = new DataOutputStream(clientSocket.getOutputStream());
			inputStreamString = new DataInputStream(clientSocket.getInputStream());
			messageDigest = MessageDigest.getInstance("MD5");

			// welcome hands
			send(welcomeMessage);
			if (receive() < 0) {
				outputStreamString.writeBytes("Sorry, I can't recognize you as a correct client");
				outputStreamString.close();
				inputStreamString.close();
				clientSocket.close();
				System.out.println("Incorrect client from " + clientSocket.getInetAddress() + ", connection terminated.");
				return;
			} else
				System.out.println("Client connected from " + clientSocket.getInetAddress());

			send((new Date()) + "  Type ? for help\n");

			// main loop
			StringTokenizer st;
			while (true) {
				if (receive() < 0)
					break;
				st = new StringTokenizer(new String(message));
				String command;
				if (st.countTokens() < 1) {
					send("");
					continue;
				}
				command = st.nextToken().toLowerCase();
				System.out.println(command);
				if (command.equals("ls") || command.equals("dir"))
					dir(st);
				else if (command.equals("put"))
					put(st);
				else if (command.equals("get"))
					get(st);
				else if (command.equals("cd"))
					chdir(st);
				else if (command.equals("cd.."))
					cdup();
				else if (command.equals("pwd"))
					pwd();
				else if (command.equals("quit") || command.equals("bye") || command.equals("close")
						|| command.equals("exit"))
					break;
				else
					send("Unknown command: " + command);
			}

			System.out.println("Connection from " + clientSocket.getInetAddress() + " closed.");
			outputStreamString.close();
			inputStreamString.close();
			clientSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Error, close connection.");
			// e.printStackTrace();
		}
	}

	void dir(StringTokenizer st) throws IOException {
		File tmp = new File(home + cwd);
		String[] fileList = tmp.list();
		String msg = "Server Directory: " + home + cwd + "\n";
		for (int i = 0; i < fileList.length; i++) {
			tmp = new File(fileList[i]);
			// if (tmp.isDirectory()) msg=msg+"<DIR>\t"+fileList[i]+"\n";
			if (!tmp.isDirectory())
				msg = msg + " " + tmp.length() + "\t" + fileList[i] + "\n";
			else
				msg = msg + "<DIR>\t" + fileList[i] + File.separator + "\n";
			// else msg=msg+"\t"+fileList[i]+"\n";
		}
		msg = msg + "Total " + fileList.length + " file(s)\n";
		send(msg);
	}

	void chdir(StringTokenizer st) throws IOException {
		String path;
		if (st.hasMoreTokens()) {
			path = st.nextToken();
			if (!path.startsWith(File.separator))
				path = cwd + path;
		} else
			path = File.separator;
		File tmp = new File(home + path);
		if (tmp.isDirectory() && tmp.getCanonicalPath().startsWith(home)) {
			path = tmp.getCanonicalPath() + File.separator;
			cwd = path.substring(home.length(), path.length());
			send("Enter Directory: " + cwd + "\n");
		} else
			send("Error: directory not exist\n");
	}

	void pwd() throws IOException {
		send("Current Directory: " + cwd + "\n");
	}

	void cdup() throws IOException {
		File tmp = new File(home + cwd + "..");
		String path = tmp.getCanonicalPath();
		if (path.startsWith("\\")) {
			path = path + File.separator;
			cwd = path.substring(home.length(), path.length());
			send("Enter Directory: " + cwd + "\n");
		} else
			send("Operation failed: already root directory\n");
	}

	void put(StringTokenizer st) throws IOException {
		if (!st.hasMoreTokens())
			send("Error: parameter needed.");
		else {
			String name = st.nextToken();
			if (name.startsWith("..") || name.indexOf('\\') >= 0 || name.indexOf('/') >= 0) {
				send("Error: syntax error");
			} else {
				File tmp = new File(home + cwd + name);
				 {
					send("OK");
					if (receiveFile(tmp) >= 0)
						send("File " + name + " transfered to server.");
					else
						send("Failed: maybe no permission.");
				}
			}
		}
	}

	void get(StringTokenizer st) throws IOException {
		if (!st.hasMoreTokens())
			send("Error: parameter needed.");
		else {
			String name = st.nextToken();
			if (name.startsWith("..") || name.indexOf('\\') >= 0 || name.indexOf('/') >= 0) {
				send("Error: syntax error");
			} else {
				System.out.println(home + cwd + name);
				File tmp = new File(home + cwd + name);
				if ((!tmp.isFile()) || (!tmp.canRead()))
					send("Error: no such file or permission denied.");
				else {
					
					send("OK");
					if (receive() < 0)
						return;
					sendFile(tmp);
				}
			}
		}
	}

	long receiveFile(File file) throws IOException {
			FileOutputStream fout = new FileOutputStream(file);
			long len = inputStreamString.readLong();
			inputStreamString.readFully(hmac);
			if (!verify(hmac, Long.toString(len).getBytes(), keypad)) {
				fout.close();
				return -1;
			}
			
			byte[] buffer = new byte[4096];
			for (long i = 0; i < len / 4096; i++) {
				inputStreamString.readFully(buffer);
				fout.write(buffer);
				messageDigest.update(buffer);
			}
			int restlen = (int) (len % 4096);
			if (restlen > 0) {
				inputStreamString.readFully(buffer, 0, restlen);
				fout.write(buffer, 0, restlen);
				messageDigest.update(buffer, 0, restlen);
			}
			fout.close();
			inputStreamString.readFully(hmac);
			messageDigest.update(passwd);
			byte[] hmac1 = messageDigest.digest(keypad);
		
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
		keypad = getNewKeypad();
		outputStreamString.write(keypad);
		FileInputStream fin = new FileInputStream(file);
		long len = file.length();
		outputStreamString.writeLong(len);
		messageDigest.update(Long.toString(len).getBytes());
		messageDigest.update(keypad);
		hmac = messageDigest.digest(passwd);
		outputStreamString.write(hmac);
		
		byte[] buffer = new byte[4096];
		for (long i = 0; i < len / 4096; i++) {
			fin.read(buffer);
			outputStreamString.write(buffer);
			messageDigest.update(buffer);
		}
		int restlen = (int) (len % 4096);
		if (restlen > 0) {
			fin.read(buffer, 0, restlen);
			outputStreamString.write(buffer, 0, restlen);
			messageDigest.update(buffer, 0, restlen);
		}
		fin.close();
		messageDigest.update(keypad);
		hmac = messageDigest.digest(passwd);
		outputStreamString.write(hmac);
			
	}

	static String readline() throws IOException {
		char lastChar = 0;
		InputStreamReader stdin = new InputStreamReader(System.in);
		char[] buf = new char[1024];
		int i = 0;
		buf[i] = (char) stdin.read();
		if ((buf[i] == '\n' && lastChar == '\r') || (buf[i] == '\r' && lastChar == '\n'))
			buf[i] = (char) stdin.read();
		while (buf[i] != '\n' && buf[i] != '\r') {
			i++;
			buf[i] = (char) stdin.read();
		}
		lastChar = buf[i];
		if (i < 1)
			return new String("");
		else
			return new String(buf, 0, i);
	}

	public static void main(String[] args) throws IOException {
		ServerSocket serverSocket = null;
		boolean listening = true;
		int serverPort = 8889;
		String welcomeMessage = "FTP Server Version 1.0";
		String passwd = null;
		String root = ".";
		if (args.length >= 1) {
			root = args[0];
			if (args.length >= 2)
				serverPort = Integer.parseInt(args[1]);
		}
		System.out.println(welcomeMessage);
		System.out.print("Please enter your password:");
		passwd = readline();
		File tmp = new File(root);
		root = tmp.getCanonicalPath();
		if (!tmp.isDirectory()) {
			System.out.println("Directory " + root + " doesn't exist!");
			System.exit(-1);
		}
		try {
			serverSocket = new ServerSocket(serverPort);
		} catch (IOException e) {
			System.out.println("Could not listen on port: " + serverPort);
			System.exit(-1);
		}
		System.out.println("Server running at port " + serverPort);
		System.out.println("Root directory is: " + root);
		while (listening) {
			Socket socket = serverSocket.accept();
			new ServerFTPThread(socket, passwd, welcomeMessage, root).start();
			
		}
		serverSocket.close();

	}
}
