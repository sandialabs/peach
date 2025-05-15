package peach.sarif.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.activation.MimeTypeParseException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.CodeFlow;
import com.contrastsecurity.sarif.Edge;
import com.contrastsecurity.sarif.Graph;
import com.contrastsecurity.sarif.Node;
import com.contrastsecurity.sarif.ReportingDescriptorReference;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.SarifSchema210;
import com.contrastsecurity.sarif.ThreadFlow;
import com.contrastsecurity.sarif.ThreadFlowLocation;
import com.contrastsecurity.sarif.ToolComponent;

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.EmptyGraphType;
import peach.PeachPlugin;
import peach.sarif.SarifUtils;
import peach.sarif.controller.SarifController;
import peach.sarif.model.PeachTableModelFactory.PeachAddressTableModel.Column;
import peach.sarif.model.PeachTableModelFactory.PeachTableModel;

/**
 * Parse the SARIF log into easier to use data structures. And helper functions.
 * {@link SarifController} to do any additional gui interactions
 */
public class SarifModel implements PeachTableModel {
	private SarifSchema210 sarifLog;
	private SarifController controller;

	private List<Column> tableColumns; // List of columns for creating {@link SarifResultsTableModelFactory}
	private List<Map<String, Object>> tableRows; // Row objects for table

	private static final Logger LOG = LogManager.getLogger(PeachPlugin.class);

	public SarifModel(SarifSchema210 sarifLog, SarifController controller) {
		this.sarifLog = sarifLog;
		this.controller = controller;

		tableColumns = new ArrayList<>();
		tableRows = new ArrayList<>();

		// Default columns we always have
		tableColumns.add(new Column<String>("Tool", true, String.class));
		tableColumns.add(new Column<String>("RuleId", true, String.class));
		tableColumns.add(new Column<Address>("Address", true, Address.class));
		tableColumns.add(new Column<String>("Message", true, String.class));
		tableColumns.add(new Column<String>("Kind", true, String.class));
		tableColumns.add(new Column<String>("Level", true, String.class));

		for (Run run : sarifLog.getRuns()) {
			handleRun(run);
		}
	}

	private void handleRun(Run run) {
		// We display taxonomy as new columns
		tableColumns.addAll(SarifUtils.getTaxonomyColumns(run));

		for (Result result : run.getResults()) {
			handleResult(run, result);
		}

		showArtifacts(run);
		showGraphs(run);
	}

	private void handleResult(Run run, Result result) {
		HashMap<String, Object> curTableResult = new HashMap<>();

		// Default SARIF values that should be on any results
		curTableResult.put("Tool", run.getTool().getDriver().getName());
		curTableResult.put("RuleId", SarifUtils.getRuleId(result));
		// If we can parse a listing Address we can make the table navigate there when
		// selected
		addAddress(run, result, curTableResult);
		curTableResult.put("Message", SarifUtils.getMessage(run, result));
		curTableResult.put("Kind", result.getKind().toString());
		curTableResult.put("Level", result.getLevel().toString());

		// Taxonomies are added as additional columns in the table
		addTaxonomies(run, result, curTableResult);

		// Code flows and graphs are just added to the tableResults Map not to the
		// actual table
		// For reference when a row is selected
		handleCodeFlows(run, result, curTableResult);
		handleGraphs(run, result, curTableResult);
		// handleAttachments

		// The property bag is used for additional Ghidra GUI interactions and other
		// custom things
		handleProperties(run, result, curTableResult);

		tableRows.add(curTableResult);
	}

	private void addAddress(Run run, Result result, HashMap<String, Object> curTableResult) {
		List<Address> resultAddrs = controller.getListingAddresses(run, result);
		if (resultAddrs.size() > 0) {
			curTableResult.put("Address", resultAddrs.get(0));
		}
	}

	private void handleGraphs(Run run, Result result, HashMap<String, Object> curTableResult) {
		if (result.getGraphs() != null) {
			List<AttributedGraph> graphs = new ArrayList<AttributedGraph>();
			for (Graph g : result.getGraphs()) {
				graphs.add(toGhidraGraph(run, g));
			}
			curTableResult.put("Graphs", graphs);
		}
	}

	private void handleCodeFlows(Run run, Result result, HashMap<String, Object> curTableResult) {
		if (result.getCodeFlows() != null) {
			List<List<Address>> codeFlows = new ArrayList<List<Address>>();
			for (CodeFlow f : result.getCodeFlows()) {
				codeFlows.add(parseCodeFlow(run, f));
			}
			curTableResult.put("CodeFlows", codeFlows);
		}
	}

	private void addTaxonomies(Run run, Result result, HashMap<String, Object> curTableResult) {
		Set<ReportingDescriptorReference> taxas = result.getTaxa();
		if (taxas != null) {
			for (ReportingDescriptorReference taxa : result.getTaxa()) {
				ToolComponent taxonomy = SarifUtils.getTaxonomy(taxa, run.getTaxonomies());
				String colName = taxonomy.getName();
				String colValue = SarifUtils.getTaxaValue(taxa, taxonomy).getId();
				curTableResult.put(colName, colValue);
			}
		}
	}

	private void handleProperties(Run run, Result result, HashMap<String, Object> curTableResult) {
		if (result.getProperties() == null) {
			return;
		}
		Map<String, Object> properties = result.getProperties().getAdditionalProperties();
		if (properties != null) {
			// Since this may make GUI changes need to put it in
			try (Transaction t = controller.getProgram().openTransaction("SARIF custom properties.")) {
				for (String key : properties.keySet()) {
					String[] splits = key.split("/");
					switch (splits[0]) {
					case "peach":
					case "viewer":
						switch (splits[1]) {
						case "table":
							// "(peach|viewer)/table/<col>": <value>
							String colName = addColumn(splits[2], properties.get(key).getClass());
							curTableResult.put(colName, properties.get(key));
						}
						break;
					case "table":
						// "table/<col>": <value>
						String colName = addColumn(splits[1], properties.get(key).getClass());
						curTableResult.put(colName, properties.get(key));
						break;
					case "listing":
						controller.handleListingAction(run, result, Arrays.copyOfRange(splits, 1, splits.length),
								properties.get(key));
						break;
					}
				}
				t.commit();
			}
		}
	}

	private String addColumn(String newColName, Class<? extends Object> colType) {
		boolean visible = true;
		// '.' is used to indicate this column should be hidden to start, but don't want
		// the .
		// as part of the column name
		if (newColName.startsWith(".")) {
			visible = false;
			newColName = newColName.substring(1);
		}
		// See if we've already added this column
		for (Column<?> c : tableColumns) {
			if (newColName.equals(c.name))
				return newColName;
		}
		tableColumns.add(new Column(newColName, visible, colType));
		return newColName;
	}

	private void showGraphs(Run run) {
		if (run.getGraphs() != null) {
			for (Graph g : run.getGraphs()) {
				controller.showGraph(toGhidraGraph(run, g));
			}
		}
	}

	private void showArtifacts(Run run) {
		if (run.getArtifacts() != null) {
			for (Artifact artifact : run.getArtifacts()) {
				try {
					controller.showArtifact(artifact);
				} catch (IOException e) {
					LOG.error("Error reading artifact: " + e.getMessage());
				} catch (MimeTypeParseException e) {
					LOG.error("Error parsing artifact type: " + e.getMessage());
				}
			}
		}
	}

	private static AttributedGraph toGhidraGraph(Run run, Graph g) {
		AttributedGraph graph = new AttributedGraph(run.getTool().getDriver().getName(), new EmptyGraphType());
		Map<String, AttributedVertex> nodeMap = new HashMap<String, AttributedVertex>();
		for (Node n : g.getNodes()) {
			// AttributedVertex node = graph.addVertex(n.getId(), n.getLabel().getText());
			// node.
			nodeMap.put(n.getId(), graph.addVertex(n.getId(), n.getLabel().getText()));
		}
		for (Edge e : g.getEdges()) {
			graph.addEdge(nodeMap.get(e.getSourceNodeId()), nodeMap.get(e.getTargetNodeId()));
		}
		return graph;
	}

	private List<Address> parseCodeFlow(Run run, CodeFlow f) {
		List<Address> addrs = new ArrayList<Address>();
		for (ThreadFlow t : f.getThreadFlows()) {
			for (ThreadFlowLocation loc : t.getLocations()) {
				Address addr = controller.locationToAddress(run, SarifUtils.getThreadFlowLocation(run, loc));
				if (addr != null)
					addrs.add(addr);
			}
		}
		return addrs;
	}

	@Override
	public List<Column> getColumns() {
		return this.tableColumns;
	}

	@Override
	public List<Map<String, Object>> getTableRows() {
		return this.tableRows;
	}

	public List<ToolComponent> getTaxonomies() {
		List<ToolComponent> taxas = new ArrayList<ToolComponent>();
		for (Run run : this.sarifLog.getRuns()) {
			if (run.getTaxonomies() != null)
				taxas.addAll(run.getTaxonomies());
		}
		return taxas;
	}
}
