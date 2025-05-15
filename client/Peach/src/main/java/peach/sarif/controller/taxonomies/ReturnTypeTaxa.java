package peach.sarif.controller.taxonomies;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import peach.sarif.controller.SarifController;
import peach.sarif.model.PeachTableModelFactory.PeachAddressTableModel.Column;
import peach.sarif.view.SarifResultsTableProvider;

/**
 * Used by {@link SarifResultsTableProvider} to add a custom taxonomy column
 *
 */
public final class ReturnTypeTaxa {
	public static DockingAction createActions(SarifResultsTableProvider provider) {

		int type_idx = Column.indexOf(provider.model.getModel().getColumns(), "return type");
		DockingAction rightClick = new DockingAction("Apply", provider.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try (Transaction t = provider.program.openTransaction("Add return types.")) {
					int[] selected = provider.filterTable.getTable().getSelectedRows();
					// provider.filterTable.getTable().getRowSorter().convertRowIndexToModel(type_idx)
					for (int idx : selected) {
						Function func = provider.program.getFunctionManager()
								.getFunctionContaining(provider.model.getAddress(idx));
						String value = (String) provider.model.getColumnValueForRow(provider.model.getRowObject(idx),
								type_idx);
						ReturnTypeTaxa.setReturnType(func, value);
					}
					t.commit();
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		rightClick.setPopupMenuData(new MenuData(new String[] { "Commit" }));
		return rightClick;
	}

	public static boolean setReturnType(Function func, String type) {
		if (type != null) {
			try {
				func.setReturnType(SarifController.parseDataType(type), SourceType.ANALYSIS);
				return true;
			} catch (InvalidInputException e) {
				e.printStackTrace();
			}
		}
		return false;
	}
}
