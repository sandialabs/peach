package peach.sarif.view;

import java.awt.image.BufferedImage;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.widgets.imagepanel.ImagePanel;
import ghidra.framework.plugintool.PluginTool;

/**
 * For displaying Image artifacts from a SARIF file
 *
 */
public class ImageArtifactDisplay extends ComponentProvider {
	public ImagePanel label;

	public ImageArtifactDisplay(PluginTool tool, String name, String owner, BufferedImage img) {
		super(tool, name, owner);
		label = new ImagePanel(new ImageIcon(img).getImage());
	}

	@Override
	public JComponent getComponent() {
		return label;
	}
}
