package burp;

import javax.swing.*;

public class RouteTable extends JTable {

    @Override
    public Class getColumnClass(int column) {
        switch (column) {
            case 0:
                return Boolean.class;
            default:
                return String.class;
        }
    }
    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0;
    }
}
