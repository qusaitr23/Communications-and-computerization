package GUI;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.awt.Color;

public class Server {

	private int port;
	private List<User> clients;
	private ServerSocket server;

	/**
	 * our main to run the server that we build to enable the client and connection
	 * between them.
	 * 
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		new Server(8080).run();
		Socket s=new Socket("127.0.0.1",8080);
		DataInputStream dos=new DataInputStream(s.getInputStream());
		String msg=dos.readUTF();
		System.out.println(msg);
	}

	/**
	 * 
	 * @param port our deafult port is 8080
	 */
	public Server(int port) {		this.port = port;
		this.clients = new ArrayList<User>();
	}

	public void run() throws IOException {
		server = new ServerSocket(port) {
			protected void finalize() throws IOException {
				this.close();
			}
		};
		System.out.println("Port >>8080<<  is now open.");

		while (true) {
			/**
			 * accepts a new client.
			 */
			Socket client = server.accept();

			/**
			 * get the nickname of the newuser.
			 */
			String nickname = (new Scanner(client.getInputStream())).nextLine();
			nickname = nickname.replace(",", ""); // ',' use for serial
			nickname = nickname.replace(" ", "_");
			System.out.println(
					"New Client: \"" + nickname + "\"\n\t     Host:" + client.getInetAddress().getHostAddress());

			/**
			 * create new User to the chat.
			 */
			User newUser = new User(client, nickname);

			/**
			 * add newUser message to list.
			 */
			this.clients.add(newUser);

			/**
			 * Welcome massege
			 */
			newUser.getOutStream().println(newUser.toString());

			/**
			 *  create a new thread for newuser incoming messages to handling
			 */
			new Thread(new UserHandler(this, newUser)).start();
		}
	}

	/**
	 * 
	 *  delete a user from the list
	 * @param user
	 */
	public void removeUser(User user) {
		this.clients.remove(user);
	}

	// send incoming msg to all Users
	public void broadcastMessages(String msg, User userSender) {
		for (User client : this.clients) {
			client.getOutStream().println(userSender.toString() + "<span>: " + msg + "</span>");
		}
	}

	// send list of clients to all Users
	public void broadcastAllUsers() {
		for (User client : this.clients) {
			client.getOutStream().println(this.clients);
		}
	}

	// send message to a User (String)
	public void sendMessageToUser(String msg, User userSender, String user) {
		boolean find = false;
		for (User client : this.clients) {
			if (client.getNickname().equals(user) && client != userSender) {
				find = true;
				userSender.getOutStream().println(userSender.toString() + " >>>> " + client.toString() + ": " + msg);
				client.getOutStream()
						.println("(<b>Private</b>)" + userSender.toString() + "<span>: " + msg + "</span>");
			}
		}
		if (!find) {
			userSender.getOutStream().println(userSender.toString() + " -> (<b>no one!</b>): " + msg);
		}
	}
}

class UserHandler implements Runnable {

	private Server server;
	private User user;

	public UserHandler(Server server, User user) {
		this.server = server;
		this.user = user;
		this.server.broadcastAllUsers();
	}

	public void run() {
		String message;

		// when there is a new message, broadcast to all
		Scanner sc = new Scanner(this.user.getInputStream());
		while (sc.hasNextLine()) {
			message = sc.nextLine();

			//  private masseges.
			if (message.charAt(0) == '@') {
				if (message.contains(" ")) {
					System.out.println("private msg : " + message);
					int firstSpace = message.indexOf(" ");
					String userPrivate = message.substring(1, firstSpace);
					server.sendMessageToUser(message.substring(firstSpace + 1, message.length()), user, userPrivate);
				}

			} else if (message.charAt(0) == '#') {
				user.changeColor(message);
				// update color for all other users
				this.server.broadcastAllUsers();
			} else {
				// update user list
				server.broadcastMessages(message, user);
			}
		}
		// end of Thread
		server.removeUser(user);
		this.server.broadcastAllUsers();
		sc.close();
	}
}

 class User {
	private static int nbUser = 0;
	private int userId;
	private PrintStream streamOut;
	private InputStream streamIn;
	private String nickname;
	private Socket client;
	private String color;

	// constructor
	public User(Socket client, String name) throws IOException {
		this.streamOut = new PrintStream(client.getOutputStream());
		this.streamIn = client.getInputStream();
		this.setClient(client);
		this.nickname = name;
		this.userId = nbUser;
		this.color = ColorInt.getColor(this.userId);
		nbUser += 1;
	}

	// change color user
	public void changeColor(String hexColor) {
		// check if it's a valid hexColor
		Pattern colorPattern = Pattern.compile("#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})");
		Matcher m = colorPattern.matcher(hexColor);
		if (m.matches()) {
			Color c = Color.decode(hexColor);
			// if the Color is too Bright don't change
			double luma = 0.2126 * c.getRed() + 0.7152 * c.getGreen() + 0.0722 * c.getBlue(); // per ITU-R BT.709
			if (luma > 160) {
				this.getOutStream().println("<b>Color Too Bright</b>");
				return;
			}
			this.color = hexColor;
			this.getOutStream().println("<b>Color changed successfully</b> " + this.toString());
			return;
		}
		this.getOutStream().println("<b>Failed to change color</b>");
	}

	//getters
	public PrintStream getOutStream() {
		return this.streamOut;
	}

	public InputStream getInputStream() {
		return this.streamIn;
	}

	public String getNickname() {
		return this.nickname;
	}

	// print user with his color
	public String toString() {

		return "<u><span style='color:" + this.color + "'>" + this.getNickname() + "</span></u>";

	}

	public Socket getClient() {
		return client;
	}

	public void setClient(Socket client) {
		this.client = client;
	}
}

class ColorInt {
	public static String[] mColors = { "#3079ab", // dark blue
			"#e15258", // red
			"#f9845b", // orange
			"#7d669e", // purple
			"#53bbb4", // aqua
			"#51b46d", // green
			"#e0ab18", // mustard
			"#f092b0", // pink
			"#e8d174", // yellow
			"#e39e54", // orange
			"#d64d4d", // red
			"#4d7358", // green
	};

	public static String getColor(int i) {
		return mColors[i % mColors.length];
	}
}