package peach.client.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.task.TaskMonitor;

/**
 * Program API, typed versions of the String based {@link PeachServerApi.java},
 * or if you want to use from other scripts.
 * 
 */
public class PeachAPI {
	public static PeachAPI instance = null;

	public static synchronized PeachAPI init(ProgramPlugin plugin) {
		return instance = new PeachAPI(plugin);
	}

	public static synchronized PeachAPI getInstance() {
		return instance;
	}

	private ProgramPlugin plugin;

	private PeachAPI(ProgramPlugin plugin) {
		this.plugin = plugin;
	}

	public Map<Function, List<Function>> getCallGraph() {
		Map<Function, List<Function>> ret = new HashMap<Function, List<Function>>();
		for (Function f : getAllFunctions()) {
			List<Function> calls = new ArrayList<Function>();
			calls.addAll(f.getCalledFunctions(TaskMonitor.DUMMY));
			ret.put(f, calls);
		}
		return ret;
	}

	public Function getFunction(String name) {
		return plugin.getCurrentProgram().getListing().getGlobalFunctions(name).get(0);
	}

	/**
	 * Get all functions of the currentProgram
	 *
	 * @return
	 */
	public List<Function> getAllFunctions() {
		Program program = plugin.getCurrentProgram();
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator funcs = functionManager.getFunctions(true);
		ArrayList<Function> toRet = new ArrayList<>();
		while (funcs.hasNext()) {
			toRet.add(funcs.next());
		}
		return toRet;
	}

	public Function getCurrentFunction() {
		return plugin.getCurrentProgram().getFunctionManager()
				.getFunctionContaining(plugin.getProgramLocation().getAddress());
	}

	public List<Function> getExternalFunctions() {
		ExternalManager exm = plugin.getCurrentProgram().getExternalManager();
		List<Function> funcs = new ArrayList<Function>();
		for (String lib : exm.getExternalLibraryNames()) {
			ExternalLocationIterator tmp = exm.getExternalLocations(lib);
			while (tmp.hasNext()) {
				ExternalLocation loc = tmp.next();
				if (loc.isFunction()) {
					funcs.add(loc.getFunction());
				}
			}
		}
		return funcs;
	}

	/**
	 * Internal helper function to get list of all high pcodes of every function
	 *
	 * @param monitor
	 * @return
	 */
	public Map<Function, List<PcodeOpAST>> getAllHighPcodes(TaskMonitor monitor) {
		Program program = plugin.getCurrentProgram();
		Map<Function, List<PcodeOpAST>> pcodes = new HashMap<>();
		FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
		while (funcs.hasNext()) {
			Function curFunc = funcs.next();
			List<PcodeOpAST> curPcodes = getHighPcode(curFunc, monitor);
			pcodes.put(curFunc, curPcodes);
		}
		return pcodes;
	}

	/**
	 * Internal helper function to get the list of high pcode for one function
	 *
	 * @param func
	 * @param monitor
	 * @return
	 */
	private List<PcodeOpAST> getHighPcode(Function func, TaskMonitor monitor) {
		HighFunction hfunc = decompFunc(func, monitor).getHighFunction();

		Iterator<PcodeOpAST> pcodes = hfunc.getPcodeOps();
		List<PcodeOpAST> pcode_list = new ArrayList<>();
		while (pcodes.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcode = pcodes.next();
			pcode_list.add(pcode);
		}
		return pcode_list;
	}

	/**
	 * Internal helper function to decompile a function
	 *
	 * @param f
	 * @param monitor
	 * @return
	 */
	public DecompileResults decompFunc(Function f, TaskMonitor monitor) {
		Program program = plugin.getCurrentProgram();
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(program);
		monitor.setMessage("Decompiling: " + f.getName());
		DecompileResults res = decompiler.decompileFunction(f, 0, monitor);
		return res;
	}

	public List<Instruction> getInstructions(Function func) {
		List<Instruction> instrs = new ArrayList<Instruction>();
		Listing listing = plugin.getCurrentProgram().getListing();
		for (Address addr : func.getBody().getAddresses(true)) {
			Instruction instr = listing.getInstructionAt(addr);
			if (instr != null) {
				instrs.add(instr);
			}
		}
		return instrs;
	}

	/**
	 * Internal helper function to filter characters that normally cause problems
	 * for workflows
	 *
	 * @param pcodes
	 * @return
	 */
	public static Map<Function, String> filterPcodes(Map<Function, List<PcodeOpAST>> pcodes) {
		Map<Function, String> toRet = new HashMap<>();
		for (Map.Entry<Function, List<PcodeOpAST>> entry : pcodes.entrySet()) {
			toRet.put(entry.getKey(), parse_pcodes(entry.getValue()));
		}
		return toRet;
	}

	/**
	 * Actual function that strips problematic characters
	 *
	 * @param pcodes
	 * @return
	 */
	private static String parse_pcodes(List<PcodeOpAST> pcodes) {
		StringBuilder toReturn = new StringBuilder();
		for (PcodeOpAST pcode : pcodes) {
			toReturn.append("\"");
			toReturn.append(pcode.getMnemonic().replace(" ", ""));
			for (Varnode input : pcode.getInputs()) {
				toReturn.append(input.toString().replace(" ", "_").replace("\n", "").replace("\"", "").replace(",", "")
						.replace("\r", ""));
			}
			toReturn.append("\"");
		}
		return toReturn.toString();
	}

	public Address getAddress(String s) {
		return getAddress(Long.parseLong(s));
	}

	public Address getAddress(Long l) {
		return plugin.getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getAddress(l);
	}

}
