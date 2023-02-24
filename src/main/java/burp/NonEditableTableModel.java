package burp;

import javax.swing.table.DefaultTableModel;

public class NonEditableTableModel extends DefaultTableModel {

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}
