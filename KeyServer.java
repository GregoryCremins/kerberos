package kerberos;

import cipher.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Function to handle running a key server
 * @author Gregory Cremins
 * @version 5/10/2015
 */
public class KeyServer 
{

	public static void main(String[] args)
	{
		//set up the serverport
		int serverPort = Integer.parseInt(args[0]);
		//get the keys and ports
		ArrayList<Integer> ports = new ArrayList<Integer>();
		ArrayList<byte[]> keys = new ArrayList<byte[]>();
		for(int i = 1; i < args.length; i++)
		{
			//get the port
			int target = Integer.parseInt(args[i]);
			ports.add(target);
			//then get the key, which has to be taken 2 digits at a time then thrown into byte array
			String key = args[i+1];
			byte[] newKey = new byte[8];
			int index = 0;
			while (key.length() > 0)
			{
				byte targetByte = (byte)Integer.parseInt(key.substring(0,2), 16);
				newKey[index] = targetByte;
				index++;
				key = key.substring(2);
			}
			keys.add(newKey);
			i++;
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
				
				//read port A
				byte[] portByte = new byte[2];
				portByte[0] = (byte) Integer.parseInt(br.readLine());
				portByte[1] = (byte) Integer.parseInt(br.readLine());
				ByteBuffer wrapped = ByteBuffer.wrap(portByte);
				int portA = wrapped.getShort();
				//read port B
				
				byte[] portBByte = new byte[2];
				portByte[0] = (byte) Integer.parseInt(br.readLine());
				portByte[1] = (byte) Integer.parseInt(br.readLine());
				 wrapped = ByteBuffer.wrap(portByte);
				int portB = wrapped.getShort();
				//get AB keys that are on the server already
				byte[] aKey = keys.get(ports.lastIndexOf(portA));
				byte[] bKey = keys.get(ports.lastIndexOf(portB));
				
				//generate Kab
				SecureRandom sr = new SecureRandom();
				byte[] abKey = new byte[8];
				sr.nextBytes(abKey);
				//DES(Ka, Kab)
				String toA = "";
				DES des = new DES("sboxes_default");
				byte[] toALong = des.encrypt(aKey, abKey);
				
				//DES(Ka, DES(Kb, Kab))
				byte[] toBLong = des.encrypt(aKey, des.encrypt(bKey, abKey));
				
				//then send both to A
				//first send toALong
				for(int i = 0; i < toALong.length; i++)
				{
					w.println(toALong[i]);
					w.flush();
				}
				for(int j = 0; j < toALong.length; j++)
				{
					w.println(toBLong[j]);
					w.flush();
				}
				//terminate connection, because thats all it needs to do.
				System.out.println("SESSION KEYS GENERATED");
			}
		}
		catch (IOException e) 
		{
			System.out.println("Error: cannot create server on that port");
			System.exit(1);
		}
		
	}
}
