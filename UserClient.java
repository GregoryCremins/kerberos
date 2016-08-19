package kerberos;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import cipher.CBC;
import cipher.DES;

/**
 * Class to handle running the userclient which connects to userserver and chats with the other suser
 * @author Greg
 *
 */
public class UserClient
{
	public static void main(String[] args)
	{
		String ksHost = args[0];
		int ksPort = Integer.parseInt(args[1]);
		String otherHost = args[2];
		int otherPort = Integer.parseInt(args[3]);
		int userPort = Integer.parseInt(args[4]);
		String key = args[5];
		//read in userkey
		byte[] aKey = new byte[8];
		int index = 0;
		while (key.length() > 0)
		{
			byte targetByte = (byte)Integer.parseInt(key.substring(0,2), 16);
			aKey[index] = targetByte;
			index++;
			key = key.substring(2);
		}
		//alright parameters read
		//first connect to ks
		
		try
		{
			Socket hostSocket = new Socket(ksHost, ksPort);
			System.out.println("CONNECTED");
			BufferedReader br = new BufferedReader(new InputStreamReader(hostSocket.getInputStream()));
			PrintWriter w = new PrintWriter(hostSocket.getOutputStream());
			
			
			//send the two ports
			String userPortString = Integer.toHexString(userPort);
			int userPortByte1 = Integer.parseInt(userPortString.substring(0,2), 16);
			int userPortByte2 = Integer.parseInt(userPortString.substring(2), 16);
			w.println(userPortByte1);
			w.flush();
			w.println(userPortByte2);
			w.flush();
			String otherPortString = Integer.toHexString(otherPort);
			int otherPortByte1 = Integer.parseInt(otherPortString.substring(0,2), 16);
			int otherPortByte2 = Integer.parseInt(otherPortString.substring(2), 16);
			w.println(otherPortByte1);
			w.flush();
			w.println(otherPortByte2);
			w.flush();
			
			//receive the DESa VALUES
			byte[] desA = new byte[8];
			for(int i = 0; i < desA.length; i++)
			{
				desA[i] = (byte)Integer.parseInt(br.readLine());
			}
			DES des = new DES("C:\\users\\greg\\desktop\\sboxes_default");
			byte[] abKey = des.decrypt(aKey, desA);
			//recieve the DESab values
			byte[] desAB = new byte[8];
			for(int j = 0; j < desA.length; j++)
			{
				desAB[j] = (byte)Integer.parseInt(br.readLine());
			}
			byte[] bkey  = des.decrypt(aKey, desAB);
			
			hostSocket.close();
			br.close();
			w.close();
			
			//then we need to send the message to b
			Socket hostSocket2 = new Socket(otherHost, otherPort);
			BufferedReader br2 = new BufferedReader(new InputStreamReader(hostSocket2.getInputStream()));
			PrintWriter w2 = new PrintWriter(hostSocket2.getOutputStream());
			
			//then send desAB
			for(int k = 0; k < desAB.length; k++)
			{
				w2.println(bkey[k]);
				w2.flush();
			}
			//then we begin the input output loop
			BufferedReader inReader = new BufferedReader(new InputStreamReader(System.in));
			
			String systemIn = "";

			while((systemIn = inReader.readLine()) != null)
			{
				CBC cbc = new CBC(des);
				byte[] targetBytes = systemIn.getBytes("UTF-8");
				byte[] sentMessage = cbc.encrypt(abKey, targetBytes);
				w2.println(sentMessage.length);
				w2.flush();
				for (int l = 0; l < sentMessage.length; l++)
				{
					//System.out.println(sentMessage[l]);
					w2.println(sentMessage[l]);
					w2.flush();
				}
				//then read in bytes from server
				//first read in size
				int size = Integer.parseInt(br2.readLine());
				byte[] encryptedMessage = new byte[0];
				String target = "";
				for(int l = 0; l < size; l++)
				{
					byte inKB = (byte)Integer.parseInt(br2.readLine());
					//System.out.println(inKB);
					encryptedMessage = addByte(encryptedMessage, inKB);
				}
				
				//then decrypt message
				byte[] decrypted = cbc.decrypt(abKey, encryptedMessage);
				System.out.println(new String(decrypted, "UTF-8"));
				
			}
			
			
			
		} 
		catch (UnknownHostException e) 
		{
			System.out.println("ERROR: UNKNOWN HOST FOR KEY SERVER");
			System.exit(1);
		} 
		catch (IOException e)
		{
			System.out.println("IOERROR: Connection lost to other user.");
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

	/**
	 * Function to convert a byte[] to a hex string
	 * @param bytes the byte[] to be converted
	 * @return the hext string representation of the byte[]
	 */
	public static String bytesToHex(byte[] bytes) 
	{
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
