package kerberos;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import cipher.CBC;
import cipher.DES;

/**
 * Class to handle making a user server which listens for another user and chats with them
 * 
 * @author Gregory Cremins
 * @version 5/10/2015
 *
 */
public class UserServer {

	public static void main(String[] args) {
		//set up the serverport
				int serverPort = Integer.parseInt(args[0]);
				//get the keys and ports
				//get the key, which has to be taken 2 digits at a time then thrown into byte array
					String key = args[1];
					byte[] bKey = new byte[8];
					int index = 0;
					while (key.length() > 0)
					{
						byte targetByte = (byte)Integer.parseInt(key.substring(0,2), 16);
						bKey[index] = targetByte;
						index++;
						key = key.substring(2);
					}
					
				try 
				{
					ServerSocket server = new ServerSocket(serverPort);
					while(!server.isClosed())
					{
						System.out.println("SEARCHING");
						Socket clientSocket = server.accept();
						System.out.println("CONNECTED");
						BufferedReader br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); 
						PrintWriter w = new PrintWriter(clientSocket.getOutputStream());
					
						//read in DES(Kb, Kab)
						
						byte[] desKB = new byte[8];
						for(int i = 0; i < 8; i++)
						{
							byte target = (byte)Integer.parseInt(br.readLine());
							desKB[i] = target;
						}
						

						//then decrypt it
						
						DES des = new DES("sboxes_default");
						byte[] abKey = des.decrypt(bKey, desKB);
						
						//now that we have the key we can begin the session
						//read in the message loop
						String systemIn = "1";
						BufferedReader inReader = new BufferedReader(new InputStreamReader(System.in));
						while (systemIn != null)
						{
							//read in the message
							byte[] message = new byte[0];
							//first read size of message
							int size = Integer.parseInt(br.readLine());
							for(int l = 0; l < size; l++)
							{
								byte inKB = (byte)Integer.parseInt(br.readLine());
								message = addByte(message, inKB);
							}
							CBC cbc = new CBC(des);
							byte[] endResult = cbc.decrypt(abKey, message);
							System.out.println(new String(endResult, "UTF-8"));
							//then send message
							systemIn = inReader.readLine();
							byte[] targetBytes = systemIn.getBytes("UTF-8");
							cbc = new CBC(des);
							byte[] sentMessage = cbc.encrypt(abKey, targetBytes);
							w.println(sentMessage.length);
							w.flush();
							for (int l = 0; l < sentMessage.length; l++)
							{
								w.println(sentMessage[l]);
								w.flush();
							}
						}	
						//terminate connection, because thats all it needs to do.
					}
				}
				catch (IOException e) 
				{
					System.out.println("Error: cannot create server on that port");
					System.exit(1);
				}
	}
	
	/** 
	 * Function to handle adding a byte to the end of a byte[]
	 * @param target the byte[] to be added to 
	 * @param addon the byte to be added
	 * @return the byte[] of the two combined
	 */
	public static byte[] addByte(byte[] target, byte addon)
	{
		byte[] newArray = new byte[target.length + 1];
		for(int i = 0; i < target.length; i++)
		{
			newArray[i] = target[i];
		}
		newArray[newArray.length - 1] = addon;
		return newArray;
	}

}
