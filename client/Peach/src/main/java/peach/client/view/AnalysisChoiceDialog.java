package peach.client.view;

import java.awt.BorderLayout;
import java.util.Map;
import java.util.Set;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;

import com.google.gson.JsonElement;

import docking.DialogComponentProvider;
import peach.PeachPlugin;

/**
 * Display what analytics the server says are available.
 *
 */
public class AnalysisChoiceDialog extends DialogComponentProvider {

	private PeachPlugin plugin;
	private JComboBox<String> options;
	private Map<String, JsonElement> analyses;

	public AnalysisChoiceDialog(PeachPlugin peachPlugin, Map<String, JsonElement> availAnalyses) {
		super("Select Analysis to run");
		this.analyses = availAnalyses;
		this.plugin = peachPlugin;

		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		close();
		String selectedItem = (String) this.options.getSelectedItem();
		plugin.runAnalysis(selectedItem, analyses.get(selectedItem));
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	public JComponent buildPanel() {
		options = new JComboBox<String>();
		for (String name : analyses.keySet()) {
			options.addItem(name);
		}
		JPanel panel;
		panel = new JPanel(new BorderLayout());
		panel.add(options, BorderLayout.CENTER);
		return panel;
	}

	public void setAnalyses(Set<String> analyses) {
		options.removeAllItems();
		for (String name : analyses) {
			options.addItem(name);
		}
	}
}
