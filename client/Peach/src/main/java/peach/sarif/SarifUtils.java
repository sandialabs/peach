package peach.sarif;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.activation.FileTypeMap;
import javax.activation.MimeType;
import javax.activation.MimeTypeParseException;

import org.bouncycastle.util.encoders.Base64;

import com.contrastsecurity.sarif.Address;
import com.contrastsecurity.sarif.Artifact;
import com.contrastsecurity.sarif.ArtifactContent;
import com.contrastsecurity.sarif.ArtifactLocation;
import com.contrastsecurity.sarif.Location;
import com.contrastsecurity.sarif.Message;
import com.contrastsecurity.sarif.MultiformatMessageString;
import com.contrastsecurity.sarif.PhysicalLocation;
import com.contrastsecurity.sarif.ReportingDescriptor;
import com.contrastsecurity.sarif.ReportingDescriptorReference;
import com.contrastsecurity.sarif.Result;
import com.contrastsecurity.sarif.Run;
import com.contrastsecurity.sarif.SarifSchema210;
import com.contrastsecurity.sarif.ThreadFlowLocation;
import com.contrastsecurity.sarif.ToolComponent;
import com.contrastsecurity.sarif.ToolComponentReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonSyntaxException;

import peach.sarif.model.PeachTableModelFactory.PeachAddressTableModel.Column;

public class SarifUtils {

	public static SarifSchema210 readSarif(File file) throws JsonSyntaxException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		return mapper.readValue(Files.readString(file.toPath()), SarifSchema210.class);
	}

	public static SarifSchema210 readSarif(String str) throws JsonSyntaxException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		return mapper.readValue(str, SarifSchema210.class);
	}

	public static String getRuleId(Result result) {
		String ruleId = result.getRuleId();
		if (ruleId == null)
			ruleId = result.getRule().getId();
		return ruleId;
	}

	// region artifacts
	// *********************************
	public static MimeType getArtifactMimeType(Artifact artifact) throws MimeTypeParseException {
		String type = artifact.getMimeType();
		if (type == null) {
			ArtifactLocation loc = artifact.getLocation();
			if (loc == null)
				return null;
			String filename = loc.getUri();
			type = FileTypeMap.getDefaultFileTypeMap().getContentType(filename);
		}
		return new MimeType(type);
	}

	public static ByteArrayInputStream getArtifactContent(Artifact artifact) {
		ArtifactContent content = artifact.getContents();
		if (content == null)
			return null;

		String b64 = content.getBinary();
		if (b64 != null) {
			byte[] decoded = Base64.decode(b64);
			return new ByteArrayInputStream(decoded);
		}

		String text = content.getText();
		if (text != null) {
			return new ByteArrayInputStream(text.getBytes());
		}

		return null;
	}
	// endregion

	// region taxonomies
	public static String getTaxaName(ReportingDescriptorReference taxa, Set<ToolComponent> taxonomies) {
		int i = 0;
		taxa.getIndex();
		for (ToolComponent taxonomy : taxonomies) {
			if (i == taxa.getIndex()) {
				return taxonomy.getName();
			}
		}
		return "Not Found";
	}

	public static ReportingDescriptor getTaxaValue(ReportingDescriptorReference taxa, ToolComponent taxonomy) {
		List<ReportingDescriptor> view = new ArrayList<>(taxonomy.getTaxa());
		return view.get(taxa.getIndex().intValue());
	}

	public static ToolComponent getTaxonomy(ReportingDescriptorReference taxa, Set<ToolComponent> taxonomies) {
		Long idx = taxa.getToolComponent().getIndex();
		if (idx == null) {
			List<ToolComponent> view = new ArrayList<>(taxonomies);
			return view.get(taxa.getIndex().intValue());
		}
		for (ToolComponent taxonomy : taxonomies) {
			if (taxonomy.getName().equals(taxa.getToolComponent().getName())) {
				return taxonomy;
			}
		}
		return null;
	}

	public static List<Column> getTaxonomyColumns(Run sarifRun) {
		List<Column> names = new ArrayList<>();
		Set<ToolComponent> taxonomies = sarifRun.getTaxonomies();
		if (taxonomies != null) {
			for (ToolComponent taxonomy : sarifRun.getTaxonomies()) {
				boolean visible = true;
				Map<String, Object> props;
				if (taxonomy.getProperties() != null) {
					props = taxonomy.getProperties().getAdditionalProperties();
					if (props.containsKey("visible"))
						visible = (boolean) props.get("visible");
				}
				names.add(new Column<String>(taxonomy.getName(), visible, String.class));
			}
		}
		return names;
	}
	// endregion

	// 3.52.3 reportingDescriptor lookup
	// *****************************************
	/**
	 * Get reporting descriptor of result.rule
	 * 
	 * @param run
	 * @param result
	 * @return
	 */
	public static ReportingDescriptor getRule(Run run, Result result) {
		return getReportingDescriptor(getToolComponent(run).getRules(), result.getRule(), result.getRuleIndex(),
				result.getRuleId());
	}

	/**
	 * Lookup a ReportingDescriptor given a ReportingDescriptorReference.
	 * 
	 * @param descriptors
	 * @param ref
	 * @param index
	 * @param id
	 * @return
	 */
	private static ReportingDescriptor getReportingDescriptor(Set<ReportingDescriptor> descriptors,
			ReportingDescriptorReference ref, Long index, String id) {
		if (descriptors == null)
			return null;
		String guid = null;
		if (ref != null) {
			index = ref.getIndex();
			id = ref.getId();
			guid = ref.getGuid();
		}
		int i = 0;
		for (ReportingDescriptor descriptor : descriptors) {
			if (guid != null && descriptor.getGuid().equals(guid)) {
				return descriptor;
			} else if (index.intValue() == i) {
				return descriptor;
			} else if (descriptor.getId() == id) {
				return descriptor;
			}
			i++;
		}
		return null;
	}

	// endregion

	// region 3.54.2 toolComponent lookup
	// **********************************
	public static ToolComponent getToolComponent(Run run) {
		return getToolComponent(run, null, null);
	}

	public static ToolComponent getToolComponent(Run run, ToolComponentReference ref) {
		return getToolComponent(run, ref.getIndex(), ref.getGuid());
	}

	public static ToolComponent getToolComponent(Run run, Long idx, String guid) {
		if (idx == null && guid == null)
			return run.getTool().getDriver();
		else if (idx != null)
			return (ToolComponent) run.getTool().getExtensions().toArray()[idx.intValue()];
		else {
			for (ToolComponent toolComp : run.getTool().getExtensions()) {
				if (toolComp.getGuid().equals(guid))
					return toolComp;
			}
		}
		return null;
	}
	// end region

	// region 3.11.7 Message string lookup
	// ***********************************
	public static String getMessage(Run run, Result res) {
		return getMessage(getRule(run, res), res.getMessage());
	}

	public static String getMessage(ReportingDescriptor descriptor, Message message) {
		String text = message.getText();
		if (text == null) {
			String id = message.getId();
			Map<String, MultiformatMessageString> messages = descriptor.getMessageStrings().getAdditionalProperties();
			text = messages.get(id).getText();
		}
		return text;
	}
	// endregion

	// region ThreadFlows
	public static Location getThreadFlowLocation(Run run, ThreadFlowLocation loc) {
		Location location = loc.getLocation();
		if (location == null) {
			Long idx = loc.getIndex();
			ThreadFlowLocation[] threadLocs = (ThreadFlowLocation[]) run.getThreadFlowLocations().toArray();
			for (int i = 0; i < threadLocs.length; i++) {
				if (i == idx.intValue()) {
					return threadLocs[i].getLocation();
				}
			}
		}
		return location;
	}
	// endregion

	public static Long getLongAddress(Run run, PhysicalLocation loc) {
		if (loc != null) {
			return getAddress(run, loc.getAddress()).getAbsoluteAddress();
		}
		return null;
	}

	public static Address getAddress(Run run, Address addr) {
		if (addr.getIndex() != null && addr.getIndex() > -1) {
			return run.getAddresses().get(addr.getIndex().intValue());
		}
		return addr;
	}

}
