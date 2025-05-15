package peach.sarif.controller.taxonomies;

import java.util.HashMap;
import java.util.Map;

import docking.action.DockingAction;
import peach.sarif.view.SarifResultsTableProvider;

public final class KnownTaxonomies {

	@FunctionalInterface
	public interface TaxonomyAction {
		DockingAction createActions(SarifResultsTableProvider provider);
	}

	public static Map<String, TaxonomyAction> taxonomies;
	static {
		taxonomies = new HashMap<>();
		taxonomies.put("return type", ReturnTypeTaxa::createActions);
	}
}
