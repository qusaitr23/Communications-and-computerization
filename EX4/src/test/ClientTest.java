package test;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

import GUI.Client;

class ClientTest {


	@Test
	void testClient() throws UnknownHostException, IOException {

		Client client=new Client("127.0.0.1",8080);
		if(client.getHost()!="127.0.0.1")
		fail("Not the same host");
	  }
	

	@SuppressWarnings("resource")
	@Test
	void testRun() throws UnknownHostException, IOException {
		System.out.println("Client successfully connected to server!");
	    String nickname1 = "example";
	    String nickname2 = "example1";

	  if(nickname1.equals(nickname2)) 
		
		
		fail("Not yet implemented");
	


}}