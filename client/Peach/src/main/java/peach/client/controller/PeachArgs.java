package peach.client.controller;

import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.JTextField;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import ghidra.util.Msg;
import peach.PeachPlugin;
import peach.client.view.OptionDialog;

/**
 * Converts the JSON elements from the server plugin to gui elements and handles
 * getting the values back and what not.
 */
public class PeachArgs {
	// Original info back from Peach server
	private JsonElement args;
	private String analysisName;
	private boolean isPositional;
	private PeachPlugin plugin;

	/**
	 * Used to hold analysis arguments and how to get values. If JComponent != null
	 * -> its a user selected option else its something else that needs checked from
	 * the original `args`
	 */
	private LinkedHashMap<String, JComponent> inputs;

	/**
	 *
	 * @param analysisName The name of the server "<plugin>.<analysis>"
	 * @param args         The raw json requested parameters
	 * @param plugin       To callback to actually run the server plugin
	 */
	public PeachArgs(String analysisName, JsonElement args, PeachPlugin plugin) {
		this.analysisName = analysisName;
		this.plugin = plugin;
		this.args = args;

		this.isPositional = args == null || args.isJsonArray();
		this.inputs = new LinkedHashMap<>();
	}

	/**
	 * Get the value of the arguments (options) for this analysis (creating a popup
	 * to get user input if needed) and then run the analysis
	 */
	public void selectOptions() {
		try {
			LinkedHashMap<String, JComponent> userOptions;
			if (args == null) {
				runAnalysis();
				return;
			}
			if (isPositional) {
				userOptions = getArgComponents(args.getAsJsonArray());
			} else {
				userOptions = getArgComponents(args.getAsJsonObject());
			}
			// If the user needs to select options
			if (userOptions.size() > 0) {
				// Show the option dialog
				OptionDialog options = new OptionDialog(this, userOptions);
				plugin.getTool().showDialog(options);
			} else {
				// If not just run the analysis
				runAnalysis();
			}
		} catch (Exception e) {
			e.printStackTrace();
			Msg.showError(this, plugin.getTool().getActiveWindow(), "Getting parameters failed", e);
		}
	}

	/**
	 * Tell the PeachPlugin to run the server analysis (plugin) with the selected
	 * options
	 */
	public void runAnalysis() {
		try {
			Map<String, String> argValues = getArgValues();
			plugin.sendAnalysis(analysisName, argValues, isPositional);
		} catch (InvocationTargetException e) {
			e.printStackTrace();
			Msg.showError(this, plugin.getTool().getActiveWindow(), "Getting parameters failed",
					e.getTargetException());
		} catch (Exception e) {
			e.printStackTrace();
			Msg.showError(this, plugin.getTool().getActiveWindow(), "Getting parameters failed", e);
		}
	}

	/**
	 * Iterate through the arguments and get the values for them (e.g., if its a
	 * continuation just pass it, run an API call, or grab the value from a
	 * JComponent)
	 * 
	 * @return
	 * @throws Exception
	 */
	public Map<String, String> getArgValues() throws Exception {
		Map<String, String> paramValues = new LinkedHashMap<>();

		for (String key : inputs.keySet()) {
			JComponent opt = inputs.get(key);
			// If the option is null it means that it wasn't a user selected option but
			// something else
			if (opt == null) {

				// Get the original object info
				JsonObject origParamObj;
				if (isPositional) {
					Integer origIdx = Integer.valueOf(key.split("_")[1]);
					origParamObj = args.getAsJsonArray().get(origIdx).getAsJsonObject();
				} else {
					origParamObj = args.getAsJsonObject().get(key).getAsJsonObject();
				}

				// If it's just a continuation we should be passing the info forward
				if (origParamObj.has("continuation")) {
					paramValues.put(key, origParamObj.get("continuation").getAsString());
				}
				// If it's a function call we need to evaluate it
				else {
					paramValues.put(key, plugin.api.handleMethodCall(analysisName, origParamObj));
				}
			} else if (opt instanceof JComboBox) {
				paramValues.put(key, (String) ((JComboBox<String>) opt).getSelectedItem());
			} else if (opt instanceof JTextField) {
				paramValues.put(key, ((JTextField) opt).getText());
			} else if (opt instanceof JCheckBox) {
				paramValues.put(key, String.valueOf(((JCheckBox) opt).isSelected()));
			} else if (opt instanceof JSlider) {
				paramValues.put(key, String.valueOf(((JSlider) opt).getValue()));
			}
		}
		return paramValues;
	}

	/**
	 * Get JComponents for positional arguments
	 * 
	 * @param posArgs
	 * @return
	 * @throws Exception
	 */
	private LinkedHashMap<String, JComponent> getArgComponents(JsonArray posArgs) throws Exception {
		LinkedHashMap<String, JComponent> userOptions = new LinkedHashMap<>();
		int i = 0;
		for (JsonElement o : posArgs.getAsJsonArray()) {
			String tmpName = "placeholder_" + i++;
			JComponent input = createJComponent(o);
			inputs.put(tmpName, input);
			if (input != null) {
				userOptions.put(tmpName, input);
			}
		}
		return userOptions;
	}

	/**
	 * Get JComponents for keyword arguments
	 * 
	 * @param kwArgs
	 * @return
	 * @throws Exception
	 */
	private LinkedHashMap<String, JComponent> getArgComponents(JsonObject kwArgs) throws Exception {
		LinkedHashMap<String, JComponent> userOptions = new LinkedHashMap<>();
		for (String key : kwArgs.keySet()) {
			JComponent input = createJComponent(kwArgs.get(key));
			inputs.put(key, input);
			if (input != null) {
				JPanel compPanel = new JPanel();
				JLabel label = new JLabel(key);
				compPanel.add(label);
				compPanel.add(input);
				userOptions.put(key, compPanel);
			}
		}
		return userOptions;
	}

	/**
	 * Create a JComponent based on the JsonElement from the server plugin
	 * 
	 * @param jsonElement from the server what argument it wants
	 * @return
	 * 
	 *         <pre>
	 * 			String: 
	 *         		If the string is "true" or "false":
	 *         			JComboBox
	 *         		Otherwise will be JTextField
	 *         Array:
	 *         		JComboBox of each option as an item
	 *         Object:
	 *         		If it contains a "method" key
	 * 					"method" must be a PeachServerApi.java function to call
	 * 			        if "show" key exists and is "true"
	 * 						Then the function is executed immediately and the result is recursively parsed
	 * 					else
	 * 						null; and the value is saved for later
	 *         		If it contains a "continuation" key
	 *         			the value is passed directly back to the server plugin
	 *         		If it contains a "default" key
	 *         			Must contain keys "min" and "max" and create a slider value for these
	 *         			values
	 *         </pre>
	 * 
	 * @throws Exception
	 */
	private JComponent createJComponent(JsonElement jsonElement) throws Exception {
		JComponent option = null;
		if (jsonElement.isJsonObject()) {
			// Either a method call for data, or a slider
			JsonObject obj = jsonElement.getAsJsonObject();
			if (obj.has("method")) {
				if (obj.has("show") && obj.get("show").getAsBoolean()) {
					String ret = plugin.api.handleMethodCall(this.analysisName, obj);
					JComponent comp = createJComponent(JsonParser.parseString(ret));

					// If the returned component has a default value they want selected, try and
					// select it, currently only works for combobox.
					// Example: the server lets the user select from all functions in the binary but
					// wants to default to the currently viewed function
					if (obj.has("default")) {
						JsonElement defaultValue = obj.get("default");
						if (defaultValue.isJsonObject()) {
							JsonObject defaultObj = defaultValue.getAsJsonObject();
							if (defaultObj.has("method")) {
								ret = plugin.api.handleMethodCall(this.analysisName, defaultObj);
								defaultValue = new JsonPrimitive(ret);
							}
						}

						if (comp instanceof JComboBox) {
							JComboBox<String> comboBox = (JComboBox<String>) comp;
							comboBox.setSelectedItem(defaultValue.getAsString());
						}
					}
					return comp;
				}
				return null;
			}
			if (obj.has("default")) {
				int min = obj.get("min").getAsInt();
				int max = obj.get("max").getAsInt();
				int val = obj.get("default").getAsInt();
				option = new JSlider(min, max, val);
			}
		} else if (jsonElement.isJsonArray()) {
			option = new JComboBox<String>();
			for (JsonElement ele : jsonElement.getAsJsonArray()) {
				((JComboBox<String>) option).addItem(ele.getAsString());
			}
		} else {
			// Either boolean or an arbitrary value
			String value = jsonElement.getAsString();
			if (value.equals("true") || value.equals("false")) {
				option = new JCheckBox();
				((JCheckBox) option).setSelected(value == "true");
			} else {
				option = new JTextField(value, 20);
			}
		}
		return option;
	}

	public String getAnalysisName() {
		return analysisName;
	}
}
