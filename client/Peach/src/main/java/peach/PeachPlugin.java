package peach;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Icon;

import com.contrastsecurity.sarif.SarifSchema210;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import peach.client.controller.Communicator;
import peach.client.controller.PeachArgs;
import peach.client.controller.PeachServerApi;
import peach.client.view.AnalysisChoiceDialog;
import peach.client.view.ConnectionDialog;
import peach.client.view.ConnectionDialog.ConnectionCallback;
import peach.sarif.SarifUtils;
import peach.sarif.controller.SarifController;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Peach Plugin.",
	description = "From SARIF parsing to enabling data science workflows"
)
//@formatter:on

/**
 * A {@link ProgramPlugin} for reading in sarif files and connecting to a
 * backend Peach server to run analytics
 */
public class PeachPlugin extends ProgramPlugin implements ConnectionCallback {
	// private static final Logger LOG = LogManager.getLogger(PeachPlugin.class);
	public static final Icon PEACH_ICON = ResourceManager.loadImage("images/peach_16.png");

	private static final String PEACH_HOSTNAME = "Peach_Hostname";
	private static final String PEACH_PORT = "Peach_Port";
	private static final String PEACH_LAST_READ = "Peach_Last_Read";

	private SortedMap<String, DockingAction> analysisActions = new TreeMap<>();
	private Map<Program, SarifController> sarifControllers;

	public PeachServerApi api;
	public DockingAction readLastAction;

	private Process server_process;
	private DockingAction stopAction;
	private DockingAction startAction;

	/**
	 * Initialize the controllers and build "Read" and "Connect" actions
	 * 
	 * @param tool
	 */
	public PeachPlugin(PluginTool tool) {
		super(tool);
		this.sarifControllers = new HashMap<Program, SarifController>();
		this.api = new PeachServerApi(this);
		//@formatter:off
		new ActionBuilder("Connect", getName())
			.menuPath("Peach", "Connect")
			.menuGroup("peach", "1")
			.onAction(e -> {
				ConnectionDialog connection = new ConnectionDialog(this, this.getPreference(PEACH_HOSTNAME), Integer.parseInt(this.getPreference(PEACH_PORT)));
				tool.showDialog(connection);
			})
			.buildAndInstall(tool);

		startAction = new ActionBuilder("Start Server", getName())
						  .menuPath("Peach", "Start Server")
						  .menuGroup("peach", "2")
						  .onAction(e -> {
							  GhidraFileChooser instanceDirChooser = new GhidraFileChooser(tool.getActiveWindow());
							  instanceDirChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
							  File instancedir = instanceDirChooser.getSelectedFile();

							  ProcessBuilder pb = new ProcessBuilder("peach", "-l", "localhost", "-i", instancedir.getAbsolutePath());
							  Msg.debug(this, "Running process: " + pb.command().toString());
							  pb.redirectErrorStream(true);
							  try {
								  server_process = pb.start();
								  // TODO: progress bar?
								  BufferedReader reader = server_process.inputReader();
								  String connInfo = reader.readLine();
								  Msg.debug(this, "Peach connection line: "  + connInfo);
								  if (connInfo == null) {
									  server_process.destroyForcibly();
									  server_process = null;
								  } else {
									  String regex = "Running on (\\S+):(\\d+)";
									  Pattern pattern = Pattern.compile(regex);
									  Matcher matcher = pattern.matcher(connInfo);
									  if (matcher.matches()) {
										  String host = matcher.group(1);
										  Integer port = Integer.parseInt(matcher.group(2));

										  Msg.info(this, "Server running on " + host + " " + port);

										  tool.addAction(stopAction);
										  startAction.setEnabled(false);
										  this.connect("localhost", 1124);
									  } else {
										  // Wait to see if the server failed or something else weird happened.
										  server_process.waitFor(1000, TimeUnit.MILLISECONDS);
										  if (server_process.isAlive()) {
											  Msg.showError(this, tool.getActiveWindow(), "Start Server", "Unable to get port of server: " + connInfo);
										  } else {
											  Msg.showError(this, tool.getActiveWindow(), "Start Server", "Failed to start server: " + connInfo);
										  }
										  server_process.destroyForcibly();
										  server_process = null;
									  }
								  }
							  } catch (IOException e1) {
								  Msg.showError(this, tool.getActiveWindow(), "Start Server", e1.getMessage());
								  e1.printStackTrace();
							  } catch (InterruptedException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						  })
						  .buildAndInstall(tool);
		stopAction = new ActionBuilder("Stop Server", getName())
				  		 .menuPath("Peach", "Stop Server")
				  		 .menuGroup("peach", "2")
				  		 .onAction(e -> {
				  			 server_process.destroy();
				  			 server_process = null;
				  			 tool.removeAction(stopAction);
				  			 startAction.setEnabled(true);
				  		 })
				  		 .buildAndInstall(tool);
		tool.removeAction(stopAction);

		new ActionBuilder("Read", getName())
			.menuPath("Peach", "Read File")
			.menuGroup("peach", "1")
			.onAction(e -> {
				GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());
				// Only use extensions
				ExtensionFileFilter filter = ExtensionFileFilter.forExtensions("SARIF", "sarif", "json");
				chooser.addFileFilter(filter);
				// If previous location exists start there
				File lastFile = getLastFile();
				if (lastFile.getParentFile() != null && lastFile.getParentFile().exists())
					chooser.setCurrentDirectory(getLastFile().getParentFile());
				// Read the file and save file information
				File f = chooser.getSelectedFile();
				updateReadLastAction(f);
				this.readFile(f);
			})
			.buildAndInstall(tool);
		//@formatter:on
		updateReadLastAction(null);
	}

	@Override
	protected void finalize() {
		if (this.server_process != null) {
			this.server_process.destroy();
		}
	}

	private File getLastFile() {
		String filename = getPreference(PEACH_LAST_READ);
		return new File(filename);
	}

	private void updateReadLastAction(File file) {
		if (file != null)
			Preferences.setProperty(PEACH_LAST_READ, file.getAbsolutePath());
		if (getLastFile().exists()) {
			if (tool.getAllActions().contains(readLastAction)) {
				tool.removeAction(readLastAction);
			}
			//@formatter:off
			readLastAction = new ActionBuilder("ReadLastFile", getName())
								 .menuPath("Peach", "Read Last File (" + getLastFile().getName() + ")")
								 .menuGroup("peach", "1")
								 .onAction(e -> {
									 File f = getLastFile();
									 if (f.exists()) {
										 this.readFile(getLastFile());								 
									 } else {
										 Msg.showError(tool, tool.getActiveWindow(), "File not found", f.getAbsolutePath() + " no longer exists.");
										 updateReadLastAction(null);
									 }
								 })
								 .build();

			//@formatter:on
			tool.addAction(readLastAction);
		} else {
			if (tool.getAllActions().contains(readLastAction)) {
				tool.removeAction(readLastAction);
				readLastAction = null;
			}
		}
	}

	/**
	 * The Connect action Used by the ConnectionDialog to set hostname and port
	 * 
	 * @param hostname
	 * @param port
	 */
	@Override
	public void connect(String hostname, int port) {
		Preferences.setProperty(PEACH_HOSTNAME, hostname);
		Preferences.setProperty(PEACH_PORT, Integer.toString(port));
		Map<String, JsonElement> analyses;
		try {
			analyses = getServerAnalyses();
			setAnalysisMenuActions(analyses);
			tool.showDialog(new AnalysisChoiceDialog(this, analyses));
		} catch (IOException e) {
			Msg.showError(this, tool.getActiveWindow(), "Connection Error", "Unable to connect: " + e.getMessage());
		}
	}

	/**
	 * The Read File action
	 * 
	 * @param file
	 */
	public void readFile(File file) {
		if (file != null) {
			try {
				showSarif(file.getName(), SarifUtils.readSarif(file));
			} catch (JsonSyntaxException | IOException e) {
				Msg.showError(this, tool.getActiveWindow(), "File parse error",
						"Invalid Sarif File.\n\n" + e.getMessage());
			}
		}
	}

	/**
	 * Connected to the server and get list of available plugins.analyses
	 * 
	 * @return
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public Map<String, JsonElement> getServerAnalyses() throws UnknownHostException, IOException {
		String hostname = this.getPreference(PEACH_HOSTNAME);
		Integer port = Integer.valueOf(this.getPreference(PEACH_PORT));
		Communicator com = new Communicator(hostname, port);
		JsonArray plugins = com.getPlugins().get("result").getAsJsonArray();

		Map<String, JsonElement> availAnalyses = parsePlugins(plugins);

		return availAnalyses;
	}

	/**
	 * Helper method to parse return analyses array into a Map
	 * 
	 * @param plugins
	 * @return
	 */
	private Map<String, JsonElement> parsePlugins(JsonArray plugins) {
		Map<String, JsonElement> availAnalyses = new HashMap<String, JsonElement>();
		for (JsonElement analysis : plugins) {
			String methodname = analysis.getAsJsonObject().get("method").getAsString();
			JsonElement params = analysis.getAsJsonObject().get("params");
			availAnalyses.put(methodname, params);
		}
		return availAnalyses;
	}

	/**
	 * Create the `Peach > Run > <Plugin> > <analysis>` menu options
	 * 
	 * @param analyses
	 */
	public void setAnalysisMenuActions(Map<String, JsonElement> analyses) {
		// Remove previous server actions
		for (DockingAction action : analysisActions.values()) {
			tool.removeAction(action);
		}
		analysisActions.clear();

		// Add current set of actions
		for (String methodname : analyses.keySet()) {
			List<String> menuPath = new ArrayList<String>();
			menuPath.add("Peach");
			menuPath.add("Run");
			Collections.addAll(menuPath, methodname.split("\\."));
			//@formatter:off
			DockingAction action = new ActionBuilder(methodname, getName())
								   		.menuPath(menuPath.toArray(new String[0]))
								   		.onAction(e -> runAnalysis(methodname, analyses.get(methodname)))
								   		.buildAndInstall(tool);
			//@formatter:on
			analysisActions.put(methodname, action);
		}
	}

	/**
	 * Parse the analysis needed options and optionally show the dialog. This will
	 * then ultimately call sendAnalysis within PeachArgs.
	 * 
	 * @param serverPluginName
	 * @param requestedData
	 */
	public void runAnalysis(String serverPluginName, JsonElement requestedData) {
		new PeachArgs(serverPluginName, requestedData, this).selectOptions();
	}

	/**
	 * Do the Communication to the backend server based on the selected param info
	 *
	 * @param serverPluginName
	 * @param paramValues
	 * @param isPositional
	 */
	public void sendAnalysis(String serverPluginName, Map<String, String> paramValues, boolean isPositional) {
		String hostname = this.getPreference(PEACH_HOSTNAME);
		Integer port = Integer.valueOf(this.getPreference(PEACH_PORT));
		Communicator com = new Communicator(hostname, port);

		Map<String, Object> request = new HashMap<>();
		request.put("method", serverPluginName);
		if (isPositional) {
			request.put("params", paramValues.values());
		} else {
			request.put("params", paramValues);
		}
		JsonObject result = com.runPlugin(new Gson().toJson(request));

		// Handle Response
		if (result == null) {
			Msg.showError(this, tool.getActiveWindow(), "Server Error", "Check the server for an error");
		} else if (result.has("error")) {
			JsonObject error = result.get("error").getAsJsonObject();
			Msg.showError(this, tool.getActiveWindow(), "Plugin run error", error.get("message").getAsString());
		} else if (result.has("result")) {
			if (result.get("result").isJsonArray()) {
				// Returned a new set of analytics that needs to be selected
				tool.showDialog(new AnalysisChoiceDialog(this, parsePlugins(result.get("result").getAsJsonArray())));
			} else if (result.get("result").isJsonObject()) {
				// Returned a result to actually show
				handleServerAnalysisResult(serverPluginName, result.get("result").getAsJsonObject());
			} else {
				Msg.showError(this, tool.getActiveWindow(), serverPluginName, "Unknown result type");
			}
		}
	}

	/**
	 * If the plugin return a result object, handle it.
	 * 
	 * @param serverPluginName
	 * @param result
	 */
	public void handleServerAnalysisResult(String serverPluginName, JsonObject result) {
		if (result.has("runs")) {
			// Returned a sarif log
			try {
				showSarif(serverPluginName, SarifUtils.readSarif(new Gson().toJson(result)));
			} catch (JsonSyntaxException | IOException e) {
				Msg.showError(this, tool.getActiveWindow(), "Plugin result parse error",
						"Invalid SarifLog: " + e.getMessage());
			}
		} else if (result.has("method")) {
			// Need more option selection
			runAnalysis(result.get("method").getAsString(), result.get("params"));
		} else if (result.has("notification")) {
			// Show a notification
			Msg.showInfo(this, tool.getActiveWindow(), serverPluginName, result.get("notification").getAsString());
		}
	}

	/**
	 * Helper function so we have default values.
	 * 
	 * @param property name of property to get
	 * @return saved property or an optionally set default value
	 */
	private String getPreference(String property) {
		String default_value = "";
		switch (property) {
		case PEACH_HOSTNAME:
			default_value = "localhost";
			break;
		case PEACH_PORT:
			default_value = "1124";
			break;
		}
		String value = Preferences.getProperty(property);
		return value != null ? value : default_value;
	}

	/**
	 * Ultimately both selections could end up calling this to actually show
	 * something on the Ghidra gui
	 *
	 * @param logName
	 * @param sarif
	 */
	public void showSarif(String logName, SarifSchema210 sarif) {
		if (!sarifControllers.containsKey(this.getCurrentProgram())) {
			sarifControllers.put(currentProgram, new SarifController(this, currentProgram));
		}
		sarifControllers.get(currentProgram).show(logName, sarif);
	}

	/**
	 * Helper function for UI interactions, since `setSelection` is protected.
	 * 
	 * @param addrs
	 */
	public void makeSelection(List<Address> addrs) {
		AddressSet selection = new AddressSet();
		for (Address addr : addrs) {
			selection.add(addr);
		}
		this.setSelection(selection);
	}
}
