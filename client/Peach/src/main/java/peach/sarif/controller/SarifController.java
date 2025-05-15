package peach.sarif.controller;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.activation.MimeType;
import javax.activation.MimeTypeParseException;
import javax.imageio.ImageIO;

import org.python.jline.internal.Log;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.Location;
import com.contrastsecurity.sarif.LogicalLocation;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.SarifSchema210;

import docking.widgets.table.ObjectSelectedListener;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.EmptyGraphType;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.GraphException;
import ghidra.util.exception.InvalidInputException;
import peach.PeachPlugin;
import peach.sarif.SarifUtils;
import peach.sarif.model.SarifModel;
import peach.sarif.view.ImageArtifactDisplay;
import peach.sarif.view.SarifResultsTableProvider;
import resources.ResourceManager;

/**
 * Controller for handling interactions between the SARIF log file and Ghidra
 */
public class SarifController implements ObjectSelectedListener<Map<String, Object>> {

	private Program program;
	private ColorizingService coloringService;
	private FlatProgramAPI ghidraApi;
	private BookmarkManager bookmarkManager;
	private PeachPlugin plugin;

	public SarifController(PeachPlugin plugin, Program currentProgram) {
		this.plugin = plugin;
		this.program = currentProgram;
		this.coloringService = plugin.getTool().getService(ColorizingService.class);
		this.ghidraApi = new FlatProgramAPI(this.getProgram());

		this.bookmarkManager = getProgram().getBookmarkManager();
		bookmarkManager.defineType("Peach", ResourceManager.loadImage("images/peach_16.png"), Color.pink, 0);
	}

	public void show(String logName, SarifSchema210 sarif) {
		SarifModel model = new SarifModel(sarif, this);

		SarifResultsTableProvider table = new SarifResultsTableProvider(logName, this.plugin, this.getProgram(), model,
				PeachPlugin.PEACH_ICON);
		table.filterTable.addSelectionListener(this);
		table.addToTool();
		table.setVisible(true);
	}

	public void showArtifact(Artifact artifact) throws MimeTypeParseException, IOException {
		MimeType type = SarifUtils.getArtifactMimeType(artifact);
		ByteArrayInputStream content;

		if (type == null) {
			Log.debug("Artifact unknown mimetype (possibly null object)");
			return;
		}
		switch (type.getPrimaryType()) {
		case "image":
			content = SarifUtils.getArtifactContent(artifact);
			if (content != null) {
				BufferedImage img = ImageIO.read(content);
				ImageArtifactDisplay tmp = new ImageArtifactDisplay(plugin.getTool(), "Image", "Sarif Parse", img);
				tmp.setVisible(true);
			}
			break;
		}
	}

	public void showGraph(AttributedGraph graph) {
		try {
			GraphDisplayBroker service = this.plugin.getTool().getService(GraphDisplayBroker.class);
			GraphDisplay display = service.getDefaultGraphDisplay(false, null);
			GraphDisplayOptions graphOptions = new GraphDisplayOptions(new EmptyGraphType());

			display.setGraph(graph, graphOptions, "Test", false, null);
		} catch (GraphException | CancelledException e) {
			e.printStackTrace();
		}
	}

	/**
	 * If a results has "listing/<something>" in a SARIF result, this handles
	 * defining our custom API for those
	 *
	 * @param log
	 * @param result
	 * @param key
	 * @param value
	 */
	public void handleListingAction(Run run, Result result, String[] key, Object value) {
		List<Address> addrs = getListingAddresses(run, result);
		for (Address addr : addrs) {
			switch (key[0]) {
			case "comment":
				addComment(addr, CodeUnit.PLATE_COMMENT, (String) value);
				break;
			case "highlight":
				colorBackground(addr, hexToColor((String) value));
				break;
			case "bookmark":
				getProgram().getBookmarkManager().setBookmark(addr, "Peach", result.getRuleId(), (String) value);
				break;
			}
		}
	}

	public void addComment(Address addr, int type, String comment) {
		/* @formatter:off
		 *  docs/GhidraAPI_javadoc/api/constant-values.html#ghidra.program.model.listing.CodeUnit
		 *  EOL_COMMENT 0
		 *  PRE_COMMENT 1
		 *  POST_COMMENT 2
		 *  PLATE_COMMENT 3
		 *  REPEATABLE_COMMENT 4
		 * @formatter:on
		 */
		getProgram().getListing().setComment(addr, type, comment);
	}

	public void colorBackground(AddressSetView set, Color color) {
		coloringService.setBackgroundColor(set, color);
	}

	public void colorBackground(Address addr, Color color) {
		coloringService.setBackgroundColor(addr, addr, color);
	}

	public Address longToAddress(Long l) {
		return getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(l);
	}

	public static Color hexToColor(String hex) {
		return Color.decode(hex);
	}

	public boolean setReturnType(Integer addr, String type) {
		return setReturnType(ghidraApi.getFunctionContaining(longToAddress(addr.longValue())),
				SarifController.parseDataType(type));
	}

	public static boolean renameFunction(Function f, String name) {
		try {
			f.setName(name, SourceType.ANALYSIS);
			return true;
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public static boolean renameParameter(Function f, int idx, String name) {
		try {
			f.getParameter(idx).setName(name, SourceType.ANALYSIS);
			return true;
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
		}
		return false;
	}

	public static boolean setReturnType(Function f, DataType type) {
		if (type != null) {
			try {
				f.setReturnType(type, SourceType.ANALYSIS);
				return true;
			} catch (InvalidInputException e) {
				e.printStackTrace();
			}
		}
		return false;
	}
	
	public static boolean setParameterType(Function f, int idx, DataType type) {
		if (type != null) {
			try {
				f.getParameter(idx).setDataType(type, SourceType.ANALYSIS);
				return true;
			} catch (InvalidInputException e) {
				e.printStackTrace();
			}
		}
		return false;
	}	

	/**
	 * Get listing addresses associated with a result
	 *
	 * @param result
	 * @return
	 */
	public List<Address> getListingAddresses(Run run, Result result) {
		List<Address> addrs = new ArrayList<>();
		if (result.getLocations() != null && result.getLocations().size() > 0) {
			List<Location> locations = result.getLocations();
			for (Location loc : locations) {
				Address addr = locationToAddress(run, loc);
				if (addr != null) {
					addrs.add(addr);
				}
			}
		}
		return addrs;
	}

	/**
	 * Convert a SARIF location to a Ghidra Address
	 * 
	 * @param loc
	 * @return
	 */
	public Address locationToAddress(Run run, Location loc) {
		Long addr = SarifUtils.getLongAddress(run, loc.getPhysicalLocation());
		if (addr != null) {
			return longToAddress(addr);
		}

		if (loc.getLogicalLocations() != null) {
			Set<LogicalLocation> logicalLocations = loc.getLogicalLocations();
			for (LogicalLocation logLoc : logicalLocations) {
				return locationToAddress(logLoc);
			}
		}
		return null;
	}

	private Address locationToAddress(LogicalLocation logLoc) {
		if (logLoc.getKind() != null) {
			switch (logLoc.getKind()) {
			case "function":
				String fname = logLoc.getName();
				for (Function func : getProgram().getFunctionManager().getFunctions(true)) {
					if (fname.equals(func.getName())) {
						return func.getEntryPoint();
					}
				}
				break;
			default:
				Msg.error(this, "Unknown logical location to handle: " + logLoc.toString());
			}
		}
		return null;
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * When an item is selected on the table, check if it has anything special we
	 * should handle.
	 */
	@Override
	public void objectSelected(Map<String, Object> row) {
		if (row == null)
			return;
		if (row.containsKey("CodeFlows")) {
			System.out.println("Making selection" + row.get("CodeFlows"));
			for (List<Address> flow : (List<List<Address>>) row.get("CodeFlows")) {
				this.plugin.makeSelection(flow);
			}
		}
		if (row.containsKey("Graphs")) {
			for (AttributedGraph graph : (List<AttributedGraph>) row.get("Graphs")) {
				this.showGraph(graph);
			}
		}
	}

	public static DataType parseDataType(String datatype) {
		switch (datatype) {
		case "int":
			return new IntegerDataType();
		case "uint":
		case "__ssize_t":
			return new UnsignedIntegerDataType();
		case "bool":
			return new BooleanDataType();
		case "char":
			return new CharDataType();
		case "char *":
		case "FILE *":
		case "void *":
		case "whcar_t *":
		case "tm *":
			return new PointerDataType();
		case "void":
			return new VoidDataType();
		case "double":
			return new DoubleDataType();
		case "long":
			return new LongDataType();
		case "longdouble":
			return new LongDoubleDataType();
		case "ulong":
			return new UnsignedLongDataType();
		}
		return null;
	}
}
