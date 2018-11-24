package test;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import GUI.Client;



class  ServerTest {
	

	@Test
	void testSendMessageToUser() {
		
		Client client=new Client("127.0.0.1",8080);
		if(client.getHost()!="127.0.0.1")
		fail("Not the same host");
	}

}