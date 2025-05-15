package peach.sarif.model;

import java.util.List;
import java.util.Map;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import peach.sarif.model.PeachTableModelFactory.PeachAddressTableModel.Column;

/**
 * Just a generic table model that can handle an arbitrary number and type of
 * columns
 *
 */
public class PeachTableModelFactory {
	public interface PeachTableModel {
		public List<Column> getColumns();

		public List<Map<String, Object>> getTableRows();
	}

	/*
	 * Created a factory because we supply an arbitrary list of columns, and so to
	 * dynamically create the TableModel it needs to know which columns it needs in
	 * `TableColumnDescriptor` but you can't set the local variable before the
	 * `super` call
	 */
	private PeachTableModel model;

	public PeachTableModelFactory(PeachTableModel model) {
		this.model = model;
	}

	public PeachAddressTableModel createModel(String description, PluginTool tool, Program program) {
		return new PeachAddressTableModel(description, tool, program, model);
	}

	public class PeachAddressTableModel extends AddressBasedTableModel<Map<String, Object>> {
		private PeachTableModel model;

		public PeachAddressTableModel(String description, PluginTool tool, Program program, PeachTableModel model) {
			super(description, tool, program, null);
			// If this could be set before super call we wouldn't need the factory during
			// createTableColumnDescriptor
			this.model = model;
		}

		public PeachTableModel getModel() {
			return this.model;
		}

		@Override
		public Address getAddress(int row) {
			return (Address) this.getRowObject(row).get("Address");
		}

		@Override
		protected void doLoad(Accumulator<Map<String, Object>> accumulator, TaskMonitor monitor)
				throws CancelledException {
			for (Map<String, Object> row : model.getTableRows()) {
				accumulator.add(row);
			}
		}

		/**
		 * If we want columns handled better we can parameterize the type here. Had to
		 * do it for Strings so that the filterTable behaves correctly
		 */
		@Override
		protected TableColumnDescriptor<Map<String, Object>> createTableColumnDescriptor() {
			TableColumnDescriptor<Map<String, Object>> descriptor = new TableColumnDescriptor<>();
			for (Column<?> column : PeachTableModelFactory.this.model.getColumns()) {
				if (column.visible)
					descriptor.addVisibleColumn(column);
				else
					descriptor.addHiddenColumn(column);
			}
			return descriptor;
		}

		/**
		 * Type parameterized so that we can use the same class for all columns, and the
		 * FilterTable needs to have a String class to behave properly
		 *
		 * @param <T>
		 */
		public static class Column<T> extends AbstractDynamicTableColumn<Map<String, Object>, T, Object> {
			public String name;
			private boolean visible;
			private Class<T> type;

			/**
			 * @param name
			 * @param type Need to specify the type so that the filter table behaves how you
			 *             would expect
			 */
			public Column(String name, boolean visible, Class<T> type) {
				this.name = name;
				this.visible = visible;
				this.type = type;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public Class<T> getColumnClass() {
				return this.type;
			}

			@Override
			public T getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider serviceProvider) throws IllegalArgumentException {
				return (T) rowObject.get(this.name);
			}

			public static boolean contains(List<Column> l, String colName) {
				return indexOf(l, colName) != -1;
			}

			public static int indexOf(List<Column> l, String colName) {
				for (int i = 0; i < l.size(); i++) {
					if (l.get(i).name.equals(colName)) {
						return i;
					}
				}
				return -1;
			}
		}
	}
}
