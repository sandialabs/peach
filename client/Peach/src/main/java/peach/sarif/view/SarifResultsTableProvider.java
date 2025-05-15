package peach.sarif.view;

import java.awt.BorderLayout;
import java.util.Map;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JPanel;

import com.contrastsecurity.sarif.ToolComponent;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import peach.sarif.controller.taxonomies.KnownTaxonomies;
import peach.sarif.model.PeachTableModelFactory;
import peach.sarif.model.PeachTableModelFactory.PeachAddressTableModel;
import peach.sarif.model.SarifModel;

/**
 * Show the SARIF result as a table and build possible actions on the table
 *
 */
public class SarifResultsTableProvider extends ComponentProvider {

	private JComponent component;
	public SarifModel sarifModel;
	public PeachAddressTableModel model;
	public GhidraFilterTable<Map<String, Object>> filterTable;
	public Program program;
	private Plugin plugin;

	public SarifResultsTableProvider(String description, Plugin plugin, Program program, SarifModel df,
			Icon windowIcon) {
		this(description, plugin, program, df);
		this.setIcon(windowIcon);
	}

	public SarifResultsTableProvider(String description, Plugin plugin, Program program, SarifModel df) {
		super(plugin.getTool(), description, plugin.getName());
		this.plugin = plugin;
		this.sarifModel = df;
		PeachTableModelFactory factory = new PeachTableModelFactory(df);
		this.model = factory.createModel(description, plugin.getTool(), program);
		this.component = buildPanel();
		filterTable.getTable().getSelectionModel().addListSelectionListener(e -> plugin.getTool().contextChanged(this));
		this.createActions();
		this.program = program;
	}

	private JComponent buildPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		filterTable = new GhidraFilterTable<>(this.model);
		GhidraTable table = (GhidraTable) filterTable.getTable();

		GoToService goToService = this.getTool().getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());
		table.setNavigateOnSelectionEnabled(true);
		panel.add(filterTable);
		return panel;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	/**
	 * Columns are added to the table based on if they are required by the SARIF
	 * format or are a taxonomy that the SARIF file defines We "support" certain
	 * taxonomies here by if the names match adding additional context actions that
	 * can be performed
	 */
	public void createActions() {
		DockingAction selectionAction = new MakeProgramSelectionAction(this.plugin,
				(GhidraTable) filterTable.getTable());
		this.addLocalAction(selectionAction);
		// Check for taxonomies and add any custom actions
		for (ToolComponent taxa : sarifModel.getTaxonomies()) {
			if (KnownTaxonomies.taxonomies.containsKey(taxa.getName())) {
				this.addLocalAction(KnownTaxonomies.taxonomies.get(taxa.getName()).createActions(this));
			}
		}
	}
}
