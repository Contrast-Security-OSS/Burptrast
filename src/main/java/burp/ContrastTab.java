package burp;

import com.contrast.threads.BrowseVulnCheckThread;
import com.contrast.threads.ImportRoutesToSiteMapThread;
import com.contrast.Logger;
import com.contrast.threads.RefreshAppIDsThread;
import com.contrast.threads.RefreshOrgIDsThread;
import com.contrast.SortByAppNameComparator;
import com.contrast.SortByLastSeenComparator;
import com.contrast.SortType;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.threads.UpdateRouteTableThread;
import com.contrast.threads.UpdateTraceTableThread;
import com.contrast.YamlReader;
import com.contrastsecurity.exceptions.ContrastException;
import com.contrastsecurity.models.Application;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

public class ContrastTab {



    public ContrastTab(IBurpExtenderCallbacks callbacks, DataModel dataModel, Logger logger) {
        this.callbacks = callbacks;
        this.dataModel = dataModel;
        dataModel.setCorrelationIDAppender(new CorrelationIDAppender(callbacks));
        this.callbacks.registerHttpListener(dataModel.getCorrelationIDAppender());
        this.logger = logger;
        dataModel.setThreadManager(new ThreadManager());
        this.callbacks.registerExtensionStateListener(dataModel.getThreadManager());
    }

    public static String[] ROUTE_TABLE_COL_NAMES = {"Selected","Path", "Verb", "From Vuln","Last Exercised"};

    public static String[] TRACE_TABLE_COL_NAMES = {"Name","Rule","Severity"};



    private final IBurpExtenderCallbacks callbacks;
    private static Logger logger;

    private static DataModel dataModel;




    public String getTabCaption() {
        return "Burptrast Security";
    }

    public Component getUiComponent() {

        JPanel panel = new JPanel(new BorderLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        JPanel firstLine = new JPanel(new GridBagLayout());

        addStatusField(firstLine);


        // appConfig Panel contains the org and app chooser as well as the update button.
        // All of these are disabled until a creds file is selected.
        JPanel appConfig = new JPanel();
        appConfig.setBorder(BorderFactory.createTitledBorder("Application Configuration"));
        addOrgsDropDown(appConfig,gbc);
        addApplicationDropDown(appConfig,gbc);
        addApplicationSortRadioButtons(appConfig,gbc);
        firstLine.add(appConfig);
        addUpdateButton(appConfig);
        panel.add(firstLine,BorderLayout.BEFORE_FIRST_LINE);

        // add live browse panel
        JPanel browseConfig = new JPanel();
        browseConfig.setBorder(BorderFactory.createTitledBorder("Live Browse"));
        addBrowseToggle(browseConfig);
        firstLine.add(browseConfig);

        // Trace Panel, contains the Trace Table listing the found Vulnerabilities in TeamServer
        JPanel tracePanel = new JPanel(new BorderLayout());
        tracePanel.setBorder(BorderFactory.createTitledBorder("Trace Table"));
        addTraceTable(tracePanel);
        panel.add(tracePanel,BorderLayout.BEFORE_LINE_BEGINS);

        // Route Panel Contains the site map retrieved from TeamServer
        JPanel routePanel = new JPanel(new BorderLayout());
        JPanel siteMapConfigPanel = new JPanel(new GridBagLayout());
        siteMapConfigPanel.setBorder(BorderFactory.createTitledBorder("Site Map Config"));
        routePanel.setBorder(BorderFactory.createTitledBorder("Site Map"));
        routePanel.add(siteMapConfigPanel,BorderLayout.BEFORE_FIRST_LINE);
        addHttpService(siteMapConfigPanel);
        addImportRoutesToSiteMapButton(siteMapConfigPanel);
        JPanel routeCoverageStatsPanel = new JPanel();
        routeCoverageStatsPanel.setBorder(BorderFactory.createTitledBorder("Route Coverage Stats"));
        addRouteCoverage(routeCoverageStatsPanel);
        siteMapConfigPanel.add(routeCoverageStatsPanel);


        addRouteTable(routePanel);
        panel.add(routePanel,BorderLayout.CENTER);

        return panel;
    }

    private void addRouteCoverage(JPanel routeCoverageStatsPanel) {
        Components.setRouteStatsPanel(routeCoverageStatsPanel);
        Components.setRouteStatsLabel(new JLabel());
        Components.getRouteStatsLabel().setText("                     ");
        Components.getRouteStatsPanel().add(Components.getRouteStatsLabel());
    }

    /**
     * Adds Status field to the UI, this is used to communicate the current status of Burptrast
     * @param firstLine
     */
    private void addStatusField(JPanel firstLine) {
        // Status Field

        Components.setStatusPanel(new JPanel());
        Components.getStatusPanel().setBorder(BorderFactory.createTitledBorder("Status"));
        Components.setStatusLabel(new JLabel());
        Components.getStatusLabel().setText(Status.AWAITING_CREDENTIALS.getStatus());
        Components.getStatusPanel().add(Components.getStatusLabel());
        firstLine.add( Components.getStatusPanel());
    }

    /**
     * Adds the Live Browse toggle to Burptrast
     * @param browseConfig
     */
    private void addBrowseToggle(JPanel browseConfig) {
        Components.setEnableLiveBrowse(new JRadioButton("Enable"));
        Components.getEnableLiveBrowse().setEnabled(false);
        Components.setDisableLiveBrowse(new JRadioButton("Disable"));
        Components.getDisableLiveBrowse().setEnabled(false);
        ButtonGroup appGroup = new ButtonGroup();
        appGroup.add(Components.getEnableLiveBrowse());
        appGroup.add(Components.getDisableLiveBrowse());
        Components.getEnableLiveBrowse().addActionListener(e -> {
            if(!dataModel.isLiveBrowseEnabled()) {
                disableConfigDueToLiveBrowse();
                dataModel.clearTraceTable();
                dataModel.setLiveBrowseEnabled(true);
                if(dataModel.getBrowseCheckThread()!=null&&dataModel.getBrowseCheckThread().isAlive()) {
                    dataModel.getBrowseCheckThread().notifyThread();
                }
                String orgID = Components.getOrgsCombo().getSelectedItem().toString();
                String appID = dataModel.getAppNameIDMap().get(Components.getAppCombo().getSelectedItem().toString());
                TSReader reader = new TSReader(dataModel.getTsCreds(), logger,dataModel,callbacks);
                BrowseVulnCheckThread vulnCheckThread = new BrowseVulnCheckThread(reader,orgID,appID,dataModel.getCorrelationIDAppender(),callbacks,dataModel,logger);
                dataModel.getThreadManager().addToThreadList(vulnCheckThread);
                dataModel.setBrowseCheckThread(vulnCheckThread);
                dataModel.getThreadManager().getExecutor().execute(vulnCheckThread);
            }
        });
        Components.getDisableLiveBrowse().addActionListener(e -> {
            if(dataModel.isLiveBrowseEnabled()) {
                enableConfigDueToLiveBrowse();
                dataModel.setLiveBrowseEnabled(false);
                dataModel.getBrowseCheckThread().notifyThread();
                enableConfigDueToLiveBrowse();
            }
        });
        appGroup.setSelected(Components.getDisableLiveBrowse().getModel(),true);
        browseConfig.add(Components.getEnableLiveBrowse());
        browseConfig.add(Components.getDisableLiveBrowse());
    }


    /**
     * updates the route table called on Update Button press.
     * This is likely to be the slowest of all calls. As it requires multiple API Requests to populate the route table.
     * This requires one HTTP Request per endpoint to retrieve endpoint information, so larger applications may take
     * several seconds and appear to hang.
     * The requests are multithreaded to help remediate this.
     * @param orgID the Organization ID
     * @param appID the Application ID
     * @param reader configured TSReader
     * @throws IOException
     * @throws ExecutionException
     * @throws InterruptedException
     */
    private void updateRouteTable(String orgID, String appID, TSReader reader) throws IOException, ExecutionException, InterruptedException {
        UpdateRouteTableThread updateRouteTableThread = new UpdateRouteTableThread(reader,dataModel,orgID,appID,logger);
        dataModel.getThreadManager().addToThreadList(updateRouteTableThread);
        dataModel.getThreadManager().getExecutor().execute(updateRouteTableThread);
    }

    /**
     * updates the trace table with vulnerabilities
     * @param orgID the Organization ID
     * @param appID the Application ID
     * @param reader configured TSReader
     * @throws IOException
     */
    private void updateTraceTable(String orgID, String appID, TSReader reader) throws IOException {
        UpdateTraceTableThread thread = new UpdateTraceTableThread(reader,dataModel,orgID,appID,logger);
        dataModel.getThreadManager().addToThreadList(thread);
        dataModel.getThreadManager().getExecutor().execute(thread);
    }


    /**
     * Update button, updates the trace and route tables.
     * @param appConfig
     */
    private void addUpdateButton(JPanel appConfig) {
        Components.setUpdateButton(new JButton("Update"));
        Components.getUpdateButton().setEnabled(false);
        Components.getUpdateButton().addActionListener(e -> {
            if (!dataModel.getTsCreds().isEmpty()) {
                try {
                    dataModel.clearData();
                    dataModel.clearTraceTable();
                    dataModel.clearRouteTable();
                    String orgID = Components.getOrgsCombo().getSelectedItem().toString();
                    String appID = dataModel.getAppNameIDMap().get(Components.getAppCombo().getSelectedItem().toString());
                    TSReader reader = new TSReader(dataModel.getTsCreds(), logger,dataModel,callbacks);
                    updateTraceTable(orgID, appID, reader);
                    updateRouteTable(orgID, appID, reader);

                } catch (IOException | ContrastException | InterruptedException | ExecutionException ex) {
                    logger.logException("Error occurred while updating tables",ex);
                    throw new RuntimeException(ex);
                }
                Components.getImportRoutesButton().setEnabled(true);
            }
        });
        appConfig.add(Components.getUpdateButton());
    }


    private void addHttpService(JPanel panel) {
        // Configure protocol combo box
        Components.setProtocolCombo(new JComboBox<>());
        Components.getProtocolCombo().addItem("http");
        Components.getProtocolCombo().addItem("https");
        Components.getProtocolCombo().setPreferredSize(new Dimension(80, 25));
        Components.getProtocolCombo().setMinimumSize(new Dimension(80, 25));

        // Configure hostname field with minimum and preferred size
        Components.setHostNameField(new JTextField("", 20));
        Components.getHostNameField().setText("localhost");
        Components.getHostNameField().setMinimumSize(new Dimension(150, 25));
        Components.getHostNameField().setPreferredSize(new Dimension(200, 25));

        // Configure port field with minimum size to prevent collapsing
        Components.setPortNumberField(new JTextField());
        Components.getPortNumberField().setText("8080");
        Components.getPortNumberField().setMinimumSize(new Dimension(60, 25));
        Components.getPortNumberField().setPreferredSize(new Dimension(60, 25));

        // Configure app context field with minimum size
        Components.setAppContextField(new JTextField("", 20));
        Components.setAppContextField(new JTextField("", 20));
        Components.getAppContextField().setMinimumSize(new Dimension(150, 25));
        Components.getAppContextField().setPreferredSize(new Dimension(200, 25));

        // Configure the path label
        Components.setPathLabel(new JLabel());
        Components.getPathLabel().setText(getPathString());

        // Set up the path updater
        addPathUpdater();

        // Use a GridBagLayout for more control over component sizing
        panel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(2, 2, 2, 2);

        // Add protocol combo
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 0.1;
        panel.add(Components.getProtocolCombo(), c);

        // Add hostname field
        c.gridx = 1;
        c.gridy = 0;
        c.weightx = 0.4;
        panel.add(Components.getHostNameField(), c);

        // Add port field
        c.gridx = 2;
        c.gridy = 0;
        c.weightx = 0.1;
        panel.add(Components.getPortNumberField(), c);

        // Add app context field
        c.gridx = 3;
        c.gridy = 0;
        c.weightx = 0.4;
        panel.add(Components.getAppContextField(), c);

        // Add URL panel on next row, spanning all columns
        JPanel subPanel = new JPanel();
        subPanel.setBorder(BorderFactory.createTitledBorder("URL"));
        subPanel.add(Components.getPathLabel());

        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 4;
        c.weightx = 1.0;
        panel.add(subPanel, c);
    }

    private void addPathUpdater() {
        Components.getProtocolCombo().addItemListener(
                e -> Components.getPathLabel().setText(getPathString())
        );
        Components.getHostNameField().getDocument().addDocumentListener(
                new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }
                }
        );
        Components.getPortNumberField().getDocument().addDocumentListener(
                new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }
                }
        );
        Components.getAppContextField().getDocument().addDocumentListener(
                new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        Components.getPathLabel().setText(getPathString());
                    }
                }
        );
    }

    private String getPathString() {
        StringBuilder msg = new StringBuilder();
        String pathContext = Components.getAppContextField().getText();
        if(!pathContext.startsWith("/") && !pathContext.isEmpty()) {
            pathContext = "/"+pathContext;
        }
        if(Components.getPortNumberField().getText().isEmpty()) {
            msg.append(Components.getProtocolCombo().getSelectedItem())
                    .append("://")
                    .append(Components.getHostNameField().getText())
                    .append(Components.getPortNumberField().getText())
                    .append(pathContext);
        } else {
            msg.append(Components.getProtocolCombo().getSelectedItem())
                    .append("://")
                    .append(Components.getHostNameField().getText())
                    .append(":")
                    .append(Components.getPortNumberField().getText())
                    .append(pathContext);
        }
        return msg.toString();
    }



    /**
     * Adds the Route Table to the UI
     * @param panel
     */
    private void addRouteTable(JPanel panel) {
        // Create the table model first
        dataModel.setRouteTableModel(new NonEditableTableModel());
        dataModel.getRouteTableModel().setColumnIdentifiers(ROUTE_TABLE_COL_NAMES);

        // Create the route table and then set its model
        RouteTable routeTable = new RouteTable();
        routeTable.setModel(dataModel.getRouteTableModel());
        Components.setRouteTable(routeTable);

        // Configure checkbox for "Selected" column
        JCheckBox selectedCheckBox = new JCheckBox("Selected");
        selectedCheckBox.setSelected(true);
        selectedCheckBox.addActionListener(e -> {
            JCheckBox box = (JCheckBox) e.getSource();
            Boolean isSelected = box.isSelected();
            for(int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
                dataModel.getRouteTableModel().setValueAt(isSelected, i, 0);
            }
        });

        // Set up column renderers and sizes
        Components.getRouteTable().getColumnModel().getColumn(0).setHeaderRenderer(new EditableHeaderRenderer(selectedCheckBox));
        Components.getRouteTable().getColumnModel().getColumn(0).setMaxWidth(80);
        Components.getRouteTable().getColumnModel().getColumn(0).setMinWidth(80);
        Components.getRouteTable().getColumnModel().getColumn(0).setPreferredWidth(80);
        Components.getRouteTable().getColumnModel().getColumn(1).setPreferredWidth(300);
        Components.getRouteTable().getColumnModel().getColumn(2).setMaxWidth(50);
        Components.getRouteTable().getColumnModel().getColumn(3).setMaxWidth(100);
        Components.getRouteTable().getColumnModel().getColumn(4).setMaxWidth(250);
        Components.getRouteTable().getColumnModel().getColumn(4).setPreferredWidth(250);

        // Create scroll pane after table is fully configured
        JScrollPane scrollPane = new JScrollPane(Components.getRouteTable());
        Components.getRouteTable().setFillsViewportHeight(true);

        // Add sorter after everything else is set up
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(Components.getRouteTable().getModel());
        sorter.setComparator(4, new RouteTableComparator(dataModel));
        Components.getRouteTable().setRowSorter(sorter);

        panel.add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Adds the Import Route to Site Map Button. When selected, this takes the contents of the Route table, converts it
     * into the format expected by Burp and imports it into the Burp Site Map.
     * @param panel
     */
    private void addImportRoutesToSiteMapButton(JPanel panel) {
        Components.setImportRoutesButton(new JButton("Import Routes To Site Map"));
        Components.getImportRoutesButton().setEnabled(false);
        panel.add(Components.getImportRoutesButton());
        Components.getImportRoutesButton().addActionListener(e -> {
            ImportRoutesToSiteMapThread thread = new ImportRoutesToSiteMapThread(new TSReader(dataModel.getTsCreds(),logger,dataModel,callbacks),dataModel,logger,callbacks);
            dataModel.getThreadManager().addToThreadList(thread);
            dataModel.getThreadManager().getExecutor().execute(thread);
        });

    }


    /**
     * Adds the Trace Table to the UI
     * @param panel
     */
    private void addTraceTable(JPanel panel) {
        // Create the table model first
        dataModel.setTraceTableModel(new NonEditableTableModel());
        dataModel.getTraceTableModel().setColumnIdentifiers(TRACE_TABLE_COL_NAMES);

        // Create JTable with the model directly to avoid a null model state
        JTable traceTable = new JTable(dataModel.getTraceTableModel());
        Components.setTraceTable(traceTable);

        // Configure the table
        Components.getTraceTable().setFillsViewportHeight(true);

        // Create the scroll pane after the table is fully configured
        JScrollPane scrollPane = new JScrollPane(Components.getTraceTable());
        panel.add(scrollPane, BorderLayout.CENTER);

        // Add the sorter after everything else is set up
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(Components.getTraceTable().getModel());
        Components.getTraceTable().setRowSorter(sorter);
    }

    /**
     * Adds the Application Down down to the UI.
     * When a change is made to the down, it clears the contents of the Route and Trace tables.
     * @param panel
     * @param gbc
     */
    private void addApplicationDropDown(JPanel panel,GridBagConstraints gbc) {
        Components.setAppButton( new JButton("Refresh Application Names"));
        Components.getAppButton().setEnabled(false);
        Components.setAppCombo(new JComboBox<>());
        Components.getAppCombo().addActionListener(e -> {
            dataModel.clearRouteTable();
            dataModel.clearTraceTable();
        });
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 4;
        panel.add(Components.getAppButton(),gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 5;
        panel.add(Components.getAppCombo(),gbc);
        Components.getAppButton().addActionListener(e -> refreshApplications());
    }

    private void addApplicationSortRadioButtons(JPanel appConfig, GridBagConstraints gbc) {
        JPanel sortPanel = new JPanel();
        sortPanel.setBorder(BorderFactory.createTitledBorder("Application Sort"));
        Components.setSortByAppNameRadio(new JRadioButton("App Name"));
        Components.getSortByAppNameRadio().setEnabled(false);
        Components.setSortByLastSeenRadio(new JRadioButton("Last Seen"));
        Components.getSortByLastSeenRadio().setEnabled(false);
        ButtonGroup sortAppGroup = new ButtonGroup();
        sortAppGroup.add(Components.getSortByAppNameRadio());
        sortAppGroup.add(Components.getSortByLastSeenRadio());
        Components.getSortByAppNameRadio().addActionListener(e -> {
            if(dataModel.getSortType().equals(SortType.SORT_BY_LAST_SEEN)) {
                sortAppComboByAppName();
                dataModel.setSortType(SortType.SORT_BY_NAME);
            }
        });
        Components.getSortByLastSeenRadio().addActionListener(e -> {
            if(dataModel.getSortType().equals(SortType.SORT_BY_NAME)) {
                sortAppComboByLastSeen();
                dataModel.setSortType(SortType.SORT_BY_LAST_SEEN);

            }
        });
        sortAppGroup.setSelected(Components.getSortByAppNameRadio().getModel(),true);
        sortPanel.add(Components.getSortByAppNameRadio());
        sortPanel.add(Components.getSortByLastSeenRadio());
        appConfig.add(sortPanel);
    }

    private void sortAppComboByLastSeen() {
        List<Application> applications = dataModel.getApplications();
        applications.sort(new SortByLastSeenComparator());
        Components.getAppCombo().removeAllItems();
        applications.forEach(app-> Components.getAppCombo().addItem(app.getName()));
    }

    private void sortAppComboByAppName() {
        List<Application> applications = dataModel.getApplications();
        applications.sort(new SortByAppNameComparator());
        Components.getAppCombo().removeAllItems();
        applications.stream().forEach(app-> Components.getAppCombo().addItem(app.getName()));

    }

    /**
     * Logic that is called when the "Refresh Applications" Button is pressed.
     * This calls TS to get an updated list of applications for the specified Org.
     */
    private void refreshApplications() {
        if (!dataModel.getTsCreds().isEmpty()) {
            try {
                Components.getAppCombo().removeAllItems();
                dataModel.getAppNameIDMap().clear();
                    TSReader reader = new TSReader(dataModel.getTsCreds(),logger,dataModel,callbacks);
                    RefreshAppIDsThread thread  = new RefreshAppIDsThread(reader,dataModel,logger);
                    dataModel.getThreadManager().addToThreadList(thread);
                    dataModel.getThreadManager().getExecutor().execute(thread);

            } catch (ContrastException ex) {
                logger.logException("Error occurred while refreshing application list",ex);
                throw new RuntimeException(ex);
            }
        }
    }

    /**
     * Adds the Org Drop down to the UI
     * @param panel
     * @param gbc
     */
    private void addOrgsDropDown(JPanel panel,GridBagConstraints gbc) {
        Components.setOrgIdButton(new JButton("Refresh Org IDS"));
        Components.getOrgIdButton().setEnabled(false);
        Components.setOrgsCombo(new JComboBox<>());
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(Components.getOrgIdButton(),gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 3;
        panel.add(Components.getOrgsCombo(),gbc);
        Components.getOrgIdButton().addActionListener(e -> refreshOrgIDS(callbacks));
    }

    /**
     * Logic that is called when the "Refresh Org IDS" Button is pressed.
     * This calls TS to get an updated list of organizations.
     */
    public static void refreshOrgIDS(IBurpExtenderCallbacks callbacks) {
        if(!dataModel.getTsCreds().isEmpty()) {
            try {
                Components.getOrgsCombo().removeAllItems();
                TSReader reader = new TSReader(dataModel.getTsCreds(),logger,dataModel,callbacks);
                RefreshOrgIDsThread thread = new RefreshOrgIDsThread(reader,dataModel,logger);
                dataModel.getThreadManager().addToThreadList(thread);
                dataModel.getThreadManager().getExecutor().execute(thread);

            } catch (ContrastException ex) {
                JOptionPane.showMessageDialog(null, ex+
                        "\nSee Error log under extensions -> Errors for further details.");
                logger.logException("Error occurred while refreshing org list",ex);
                throw new RuntimeException(ex);
            }

        }
    }


    /**
     * Adds the File Chooser to the UI
     * When a Creds file is selected, the refresh org, refresh app and update buttons are enabled.
     * Also the Org and App Drop downs are populated by calling TeamServer with the newly selected credentials.
     * @param panel
     */



    /**
     * Enables the org, app and update buttons.
     */
    public static void enableButtons() {
        Components.getOrgIdButton().setEnabled(true);
        Components.getAppButton().setEnabled(true);
        Components.getUpdateButton().setEnabled(true);
        Components.getSortByAppNameRadio().setEnabled(true);
        Components.getSortByLastSeenRadio().setEnabled(true);
        Components.getDisableLiveBrowse().setEnabled(true);
        Components.getEnableLiveBrowse().setEnabled(true);
    }

    public static void disableConfigDueToLiveBrowse() {
        Components.getCredsFile().setEnabled(false);
        Components.getOrgIdButton().setEnabled(false);
        Components.getAppButton().setEnabled(false);
        Components.getAppCombo().setEnabled(false);
        Components.getOrgsCombo().setEnabled(false);
        Components.getUpdateButton().setEnabled(false);
        Components.getImportRoutesButton().setEnabled(false);
        Components.getSortByAppNameRadio().setEnabled(false);
        Components.getSortByLastSeenRadio().setEnabled(false);
    }

    private void enableConfigDueToLiveBrowse() {
        Components.getCredsFile().setEnabled(true);
        Components.getOrgIdButton().setEnabled(true);
        Components.getAppButton().setEnabled(true);
        Components.getAppCombo().setEnabled(true);
        Components.getUpdateButton().setEnabled(true);
        Components.getOrgsCombo().setEnabled(true);
        Components.getImportRoutesButton().setEnabled(true);
        Components.getSortByAppNameRadio().setEnabled(true);
        Components.getSortByLastSeenRadio().setEnabled(true);
    }

}
