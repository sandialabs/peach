package peach.client.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import peach.PeachPlugin;

/**
 * Used to communicate between {@link PeachPlugin.java} and the server
 *
 */
public class Communicator {
	private String hostname;
	private Integer port;

	public Communicator(String h, Integer p) {
		hostname = h;
		port = p;
	}

	public JsonObject getPlugins() throws UnknownHostException, IOException {
		Socket s = new Socket(hostname, port);
		PrintWriter out = new PrintWriter(s.getOutputStream(), true);
		BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
		out.println("{\"method\": \"get_plugins\"}\n");
		String res = in.readLine();
		JsonObject result = JsonParser.parseString(res).getAsJsonObject();
		out.close();
		in.close();
		s.close();
		return result;
	}

	public JsonObject runPlugin(String json) {
		CommunicateTask t = new CommunicateTask("Communicator", json);
		TaskLauncher.launchModal("Communicator", t);
		return t.result;
	}

	private class CommunicateTask extends Task {

		private String data;
		public JsonObject result;

		public CommunicateTask(String title, String toSend) {
			super(title);
			this.data = toSend;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				Socket s = new Socket(hostname, port);
				PrintWriter out = new PrintWriter(s.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
				out.println(data);
				monitor.setMessage("This is not a real progress bar, just a placeholder");
				result = JsonParser.parseString(in.readLine()).getAsJsonObject();
				out.close();
				in.close();
				s.close();
			} catch (IOException e) {
				Msg.error(this, "Failure running plugin: " + e.getMessage());
				throw new CancelledException(e.getMessage());
			}
		}

	}

}
