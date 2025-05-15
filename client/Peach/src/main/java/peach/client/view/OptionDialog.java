package peach.client.view;

import java.util.LinkedHashMap;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import peach.client.controller.PeachArgs;

/**
 * Display the options from a specific analytic.
 *
 */
public class OptionDialog extends DialogComponentProvider {
	private PeachArgs args;
	private LinkedHashMap<String, JComponent> components;

	public OptionDialog(PeachArgs args, LinkedHashMap<String, JComponent> components) {
		super("Select Analysis Options for: " + args.getAnalysisName());
		this.args = args;
		this.components = components;
		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		close();
		args.runAnalysis();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	public JComponent buildPanel() {
		JPanel panel;
		panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));

		for (String ele : this.components.keySet()) {
			panel.add(this.components.get(ele));
		}
		return panel;
	}
}
