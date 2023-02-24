package burp;

import javax.swing.*;
import java.awt.*;

public class Components {

    private static TextField portNumberField;
    private static TextField hostNameField;
    private static TextField appContextField;
    private static JComboBox<String> protocolCombo;
    private static JComboBox<String> orgsCombo;
    private static JComboBox<String> appCombo;
    private static JRadioButton sortByAppNameRadio;

    private static JRadioButton sortByLastSeenRadio;

    private static JButton importRoutesButton;

    private static JButton orgIdButton;
    private static JButton appButton;
    private static JButton updateButton;
    private static JTable traceTable;
    private static JTable routeTable;

    private static JLabel pathLabel;

    public static TextField getPortNumberField() {
        return portNumberField;
    }

    public static void setPortNumberField(TextField portNumberField) {
        Components.portNumberField = portNumberField;
    }

    public static TextField getHostNameField() {
        return hostNameField;
    }

    public static void setHostNameField(TextField hostNameField) {
        Components.hostNameField = hostNameField;
    }

    public static TextField getAppContextField() {
        return appContextField;
    }

    public static void setAppContextField(TextField appContextField) {
        Components.appContextField = appContextField;
    }

    public static JComboBox<String> getProtocolCombo() {
        return protocolCombo;
    }

    public static void setProtocolCombo(JComboBox<String> protocolCombo) {
        Components.protocolCombo = protocolCombo;
    }

    public static JComboBox<String> getOrgsCombo() {
        return orgsCombo;
    }

    public static void setOrgsCombo(JComboBox<String> orgsCombo) {
        Components.orgsCombo = orgsCombo;
    }

    public static JComboBox<String> getAppCombo() {
        return appCombo;
    }

    public static void setAppCombo(JComboBox<String> appCombo) {
        Components.appCombo = appCombo;
    }

    public static JRadioButton getSortByAppNameRadio() {
        return sortByAppNameRadio;
    }

    public static void setSortByAppNameRadio(JRadioButton sortByAppNameRadio) {
        Components.sortByAppNameRadio = sortByAppNameRadio;
    }

    public static JRadioButton getSortByLastSeenRadio() {
        return sortByLastSeenRadio;
    }

    public static void setSortByLastSeenRadio(JRadioButton sortByLastSeenRadio) {
        Components.sortByLastSeenRadio = sortByLastSeenRadio;
    }

    public static JButton getImportRoutesButton() {
        return importRoutesButton;
    }

    public static void setImportRoutesButton(JButton importRoutesButton) {
        Components.importRoutesButton = importRoutesButton;
    }

    public static JButton getOrgIdButton() {
        return orgIdButton;
    }

    public static void setOrgIdButton(JButton orgIdButton) {
        Components.orgIdButton = orgIdButton;
    }

    public static JButton getAppButton() {
        return appButton;
    }

    public static void setAppButton(JButton appButton) {
        Components.appButton = appButton;
    }

    public static JButton getUpdateButton() {
        return updateButton;
    }

    public static void setUpdateButton(JButton updateButton) {
        Components.updateButton = updateButton;
    }

    public static JTable getTraceTable() {
        return traceTable;
    }

    public static void setTraceTable(JTable traceTable) {
        Components.traceTable = traceTable;
    }

    public static JTable getRouteTable() {
        return routeTable;
    }

    public static void setRouteTable(JTable routeTable) {
        Components.routeTable = routeTable;
    }

    public static JLabel getPathLabel() {
        return pathLabel;
    }

    public static void setPathLabel(JLabel pathLabel) {
        Components.pathLabel = pathLabel;
    }
}
