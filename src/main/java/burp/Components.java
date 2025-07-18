package burp;

import javax.swing.*;
import java.awt.*;

public class Components {

    private static JTextField portNumberField;
    private static JTextField hostNameField;
    private static JTextField appContextField;
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

    private static JRadioButton enableLiveBrowse;

    private static JRadioButton disableLiveBrowse;

    private static JButton credsFile;

    private static JButton saveCredsFile;

    private static JLabel credentialsStatusLabel;



    private static JPanel credentialsStatusPanel;

    private static JPanel statusPanel;

    private static JLabel statusLabel;
    private static JPanel routeStatsPanel;
    private static JLabel routeStatsLabel;

    public static JTextField getPortNumberField() {
        return portNumberField;
    }

    public static void setPortNumberField(JTextField portNumberField) {
        Components.portNumberField = portNumberField;
    }

    public static JTextField getHostNameField() {
        return hostNameField;
    }

    public static void setHostNameField(JTextField hostNameField) {
        Components.hostNameField = hostNameField;
    }

    public static JTextField getAppContextField() {
        return appContextField;
    }

    public static void setAppContextField(JTextField appContextField) {
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

    public static JPanel getRouteStatsPanel() { return routeStatsPanel;}

    public static void setRouteStatsPanel(JPanel routeStatsPanel) { Components.routeStatsPanel = routeStatsPanel;}

    public static JLabel getRouteStatsLabel() { return routeStatsLabel;}

    public static void setRouteStatsLabel(JLabel routeStatsLabel) { Components.routeStatsLabel = routeStatsLabel;}

    public static JLabel getPathLabel() {
        return pathLabel;
    }

    public static void setPathLabel(JLabel pathLabel) {
        Components.pathLabel = pathLabel;
    }

    public static JRadioButton getEnableLiveBrowse() {
        return enableLiveBrowse;
    }

    public static void setEnableLiveBrowse(JRadioButton enableLiveBrowse) {
        Components.enableLiveBrowse = enableLiveBrowse;
    }

    public static JRadioButton getDisableLiveBrowse() {
        return disableLiveBrowse;
    }

    public static void setDisableLiveBrowse(JRadioButton disableLiveBrowse) {
        Components.disableLiveBrowse = disableLiveBrowse;
    }

    public static JButton getCredsFile() {
        return credsFile;
    }

    public static void setCredsFile(JButton credsFile) {
        Components.credsFile = credsFile;
    }

    public static JLabel getStatusLabel() {
        return statusLabel;
    }

    public static void setStatusLabel(JLabel statusLabel) {
        Components.statusLabel = statusLabel;
    }

    public static JButton getSaveCredsFile() {
        return saveCredsFile;
    }

    public static void setSaveCredsFile(JButton saveCredsFile) {
        Components.saveCredsFile = saveCredsFile;
    }


    public static void setButtons(boolean enabled) {
        Components.getOrgIdButton().setEnabled(enabled);
        Components.getAppButton().setEnabled(enabled);
        Components.getUpdateButton().setEnabled(enabled);
        Components.getSortByAppNameRadio().setEnabled(enabled);
        Components.getSortByLastSeenRadio().setEnabled(enabled);
        Components.getDisableLiveBrowse().setEnabled(enabled);
        Components.getEnableLiveBrowse().setEnabled(enabled);
        Components.getImportRoutesButton().setEnabled(enabled);
        Components.getCredsFile().setEnabled(enabled);
        Components.getOrgsCombo().setEnabled(enabled);
        Components.getAppCombo().setEnabled(enabled);
    }


    public static JLabel getCredentialsStatusLabel() {
        return credentialsStatusLabel;
    }

    public static void setCredentialsStatusLabel(JLabel credentialsStatusLabel) {
        Components.credentialsStatusLabel = credentialsStatusLabel;
    }

    public static JPanel getCredentialsStatusPanel() {
        return credentialsStatusPanel;
    }

    public static void setCredentialsStatusPanel(JPanel credentialsStatusPanel) {
        Components.credentialsStatusPanel = credentialsStatusPanel;
    }

    public static JPanel getStatusPanel() {
        return statusPanel;
    }

    public static void setStatusPanel(JPanel statusPanel) {
        Components.statusPanel = statusPanel;
    }
}
