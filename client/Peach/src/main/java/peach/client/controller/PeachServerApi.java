package peach.client.controller;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * These are what functions (the public ones) are available for server side
 * plugins to call, or meant for scripts to use. E.g., to get what data they
 * need to perform their analytics.
 * 
 * They are String based rather than typed so check {@link PeachAPI.java} if you
 * need types. 
 */
public class PeachServerApi {
	private ProgramPlugin plugin;
	private PeachAPI api;

	public PeachServerApi(ProgramPlugin plugin) {
		this.plugin = plugin;
		api = PeachAPI.init(plugin);
	}

	/**
	 * The meat of the json rpc, actually call the method with the passed
	 * parameters. Exposed plugin/data api is in {@link PluginApiTask}
	 *
	 * @param pluginName
	 * @param methodSig
	 * @return
	 * @throws Exception
	 */
	public String handleMethodCall(String pluginName, JsonObject methodSig) throws Exception {
		String method = methodSig.get("method").getAsString();
		// Method name should be peach.<method>
		method = method.split("\\.")[1];

		// Parse parameters
		List<String> params = new ArrayList<>();
		JsonArray jsonParams = methodSig.get("params").getAsJsonArray();
		for (JsonElement p : jsonParams) {
			params.add(p.getAsString());
		}

		// Run the call and return the result
		PluginApiTask pluginApi = this.new PluginApiTask(method, params);
		TaskLauncher.launchModal(method, pluginApi);
		if (!pluginApi.isCancelled() && pluginApi.succeeded) {
			if (method.equals("runScript")) {
				String filename = methodSig.get("file").getAsString();
				return PeachServerApi.getFileInBase64(filename);
			}
			return pluginApi.retValue;
		}
		throw pluginApi.exception;
	}

	/**
	 * Run an arbitrary script. Currently the workflow assumes that the server plugin
	 * supplied a file name and results are written there and that file will be
	 * returned.
	 *
	 * @param args
	 * @param monitor
	 * @return
	 * @throws Exception
	 */
	public String runScript(List<String> args, TaskMonitor monitor) throws Exception {
		Program program = plugin.getCurrentProgram();
		String scriptName = args.get(0);
		String[] scriptArgs = new String[args.size() - 1];
		for (int i = 1; i < args.size(); i++) {
			scriptArgs[i - 1] = args.get(i);
		}
		AddressSet set = program.getAddressFactory().getAddressSet();
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);

		PluginTool tool = analysisManager.getAnalysisTool();
		Project project = tool.getProject();

		GhidraState state = new GhidraState(tool, project, program, new ProgramLocation(program, set.getMinAddress()),
				new ProgramSelection(set), null);

		ResourceFile scriptInfo = GhidraScriptUtil.findScriptByName(scriptName);

		if (scriptInfo == null) {
			throw new IllegalAccessException("Couldn't find script: " + scriptName);
		}
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptInfo);
		if (provider == null) {
			throw new IllegalAccessException("Couldn't find script provider: " + scriptInfo);
		}

		PrintWriter writer = getOutputMsgStream(tool);

		GhidraScript script = provider.getScriptInstance(scriptInfo, writer);
		script.set(state, monitor, writer);

		script.runScript(scriptName, scriptArgs);

		return "";
	}

	private static PrintWriter getOutputMsgStream(PluginTool tool) {
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdOut();
			}
		}
		return new PrintWriter(System.out);
	}

	public String dumpBinary(List<String> args, TaskMonitor monitor) {
		Program program = plugin.getCurrentProgram();
		try {
			return getFileInBase64(program.getExecutablePath());
		} catch (IOException e) {
			Msg.showError(this, null, "File Not Found", e.getMessage());
			return null;
		}
	}

	public String getProgramInfo(List<String> args, TaskMonitor monitor) {
		Program program = plugin.getCurrentProgram();
		Map<String, String> results = new HashMap<>();
		results.put("Language", program.getLanguageID().toString());
		results.put("ExecutableFormat", program.getExecutableFormat());

		return new Gson().toJson(results);
	}

	/**
	 * Get the decompiled code for all supplied entry_points
	 *
	 * @param entry_points
	 * @param monitor
	 * @return
	 * @throws AddressFormatException
	 */
	public String getDecomp(List<String> entry_points, TaskMonitor monitor) throws AddressFormatException {
		Program program = plugin.getCurrentProgram();
		Map<String, String> results = new HashMap<>();
		List<Function> allFuncs;
		if (entry_points.size() == 0) {
			allFuncs = api.getAllFunctions();
		} else {
			allFuncs = new ArrayList<>();
			for (String entry_point : entry_points) {
				Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry_point);
				allFuncs.add(program.getFunctionManager().getFunctionContaining(addr));
			}
		}
		monitor.setMaximum(allFuncs.size());
		for (Function func : allFuncs) {
			DecompileResults decompRes = api.decompFunc(func, monitor);
			results.put(func.getEntryPoint().toString(), decompRes.getDecompiledFunction().getC());
			monitor.incrementProgress(1);
		}
		Gson gson = new Gson();
		return gson.toJson(results);
	}

	/**
	 * getAllFunctions, but just get the entrypoints and return them in a json
	 * object for use as RPC
	 *
	 * @param args    Unused - for compatability with reflection in PluginApiTask
	 * @param monitor
	 * @return
	 */
	public String getAllFunctions(List<String> args, TaskMonitor monitor) {
		Gson gson = new Gson();

		List<Function> funcs = api.getAllFunctions();
		List<String> entry_points = new ArrayList<>();
		if (args.size() > 0) {
			if (args.get(0).equals("true")) {
				funcs.addAll(api.getExternalFunctions());
			}
		}

		for (Function func : funcs) {
			entry_points.add(getFunctionName(func));
		}
		return gson.toJson(entry_points);
	}

	public String getCurrentFunction(List<String> args, TaskMonitor monitor) {
		return getFunctionName(api.getCurrentFunction());
	}

	private String getFunctionName(Function func) {
		return func.getName() + ": " + func.getEntryPoint().toString();
	}

	public String getCallGraph(List<String> args, TaskMonitor monitor) {
		Map<Function, List<Function>> callGraph = api.getCallGraph();
		Map<String, List<String>> strCallGraph = new HashMap<String, List<String>>();
		for (Function caller : callGraph.keySet()) {
			List<String> callees = new ArrayList<String>();
			for (Function callee : callGraph.get(caller)) {
				callees.add(callee.getName() + ": " + callee.getEntryPoint().toString());
			}
			strCallGraph.put(caller.getName() + ": " + caller.getEntryPoint().toString(), callees);
		}
		return new Gson().toJson(strCallGraph);
	}

	public String readFiles(List<String> args, TaskMonitor monitor) {
		List<String> files = new ArrayList<>();
		for (String fn : args) {
			try {
				files.add(getFileInBase64(fn));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return files.toString();
	}

	public static String getFileInBase64(String fileName) throws IOException {
		File file = new File(fileName);
		byte[] encoded = Base64.encodeBase64(FileUtils.readFileToByteArray(file));
		return new String(encoded, StandardCharsets.US_ASCII);
	}

	public class PluginApiTask extends Task {
		private String method;
		private List<String> methodArgs;
		public String retValue;
		public boolean succeeded;
		public Exception exception;

		public PluginApiTask(String method, List<String> methodArgs) {
			super(method);
			this.method = method;
			this.methodArgs = methodArgs;
			this.succeeded = false;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			// Use reflection to call the function
			Method f;
			try {
				f = PeachServerApi.class.getMethod(method, List.class, TaskMonitor.class);
				monitor.setMessage("Running: " + method + methodArgs.toString());
				retValue = (String) f.invoke(PeachServerApi.this, methodArgs, monitor);
				this.succeeded = true;
			} catch (Exception e) {
				this.exception = e;
			}
		}

	}
}
