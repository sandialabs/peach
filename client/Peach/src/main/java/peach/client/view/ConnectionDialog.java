package peach.client.view;

import java.awt.FlowLayout;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.DialogComponentProvider;

/**
 * To get the hostname and port to connect to a server.
 *
 */
public class ConnectionDialog extends DialogComponentProvider {

	public static interface ConnectionCallback {
		public void connect(String hostname, int port);
	}

	public JTextField hostField;
	public JTextField portField;
	private ConnectionCallback listener;

	public ConnectionDialog(ConnectionCallback listener, String hostname, int port) {
		super("Change connection endpoint");
		this.listener = listener;
		addWorkPanel(buildPanel(hostname, port));

		addOKButton();
		// addApplyButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		close();
		apply();
	}

	@Override
	protected void applyCallback() {
		apply();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	private void apply() {
		listener.connect(hostField.getText(), Integer.parseInt(portField.getText()));
	}

	private JComponent buildPanel(String hostname, int port) {
		// JPanel panel = new JPanel(new BorderLayout());
		// panel.setBorder(BorderFactory.createEmptyBorder(10,10,0,10));
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		hostField = new JTextField(20);
		portField = new JTextField(5);
		hostField.setText(hostname);
		portField.setText(Integer.toString(port));

		JPanel hostPanel = new JPanel();
		hostPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
		hostPanel.add(new JLabel("Hostname: "));
		hostPanel.add(hostField);

		JPanel portPanel = new JPanel();
		portPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
		portPanel.add(new JLabel("Port: "));
		portPanel.add(portField);

		panel.add(hostPanel);
		panel.add(portPanel);

		return panel;
	}
}
