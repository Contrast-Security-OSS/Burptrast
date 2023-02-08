package burp;

import com.contrast.HttpService;
import com.contrast.Logger;
import com.contrast.RequestResponseGenerator;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.YamlReader;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Organization;
import com.contrastsecurity.models.Trace;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class ContrastTab implements ITab{




    public ContrastTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        logger = new Logger( new PrintWriter(callbacks.getStdout(), true),new PrintWriter(callbacks.getStderr(), true));
    }

    private final IBurpExtenderCallbacks callbacks;
    private static Logger logger;
    private TextField portNumberField;
    private TextField hostNameField;
    private static JComboBox<String> protocolCombo;
    private static JComboBox<String> orgsCombo;
    private static JComboBox<String> appCombo;
    private static JButton importRoutesButton;
    private static JButton orgIdButton;
    private static JButton appButton;
    private static JButton updateButton;
    private static JTable traceTable;
    private static JTable routeTable;
    private static DefaultTableModel routeTableModel;
    private static final Map<Route,Optional<RouteCoverage>> routeCoverageMap = new HashMap<>();
    private static final List<HttpRequestResponse> vulnRequests = new ArrayList<>();
    private static File credsFile = null;
    private static final Map<String,String> appNameIDMap = new HashMap<>();
    private List<Trace> traces = new ArrayList<>();

    @Override
    public String getTabCaption() {
        return "Burptrast Security";
    }

    @Override
    public Component getUiComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        JPanel firstLine = new JPanel(new GridBagLayout());

        // BurpTrast Credentials Panel
        JPanel configPanel = new JPanel();
        configPanel.setBorder( BorderFactory.createTitledBorder("Credentials"));
        firstLine.add(configPanel);
        createFileChooser(configPanel);

        // appConfig Panel contains the org and app chooser as well as the update button.
        // All of these are disabled until a creds file is selected.
        JPanel appConfig = new JPanel();
        appConfig.setBorder(BorderFactory.createTitledBorder("Application Configuration"));
        addOrgsDropDown(appConfig,gbc);
        addApplicationDropDown(appConfig,gbc);
        firstLine.add(appConfig);
        addUpdateButton(appConfig);
        panel.add(firstLine,BorderLayout.BEFORE_FIRST_LINE);

        // Trace Panel, contains the Trace Table listing the found Vulnerabilities in TeamServer
        JPanel tracePanel = new JPanel(new BorderLayout());
        tracePanel.setBorder(BorderFactory.createTitledBorder("Trace Table"));
        addTraceTable(tracePanel);
        panel.add(tracePanel,BorderLayout.BEFORE_LINE_BEGINS);

        // Route Panel Contains the site map retrieved from TeamServer
        JPanel routePanel = new JPanel(new BorderLayout());
        JPanel subPanel = new JPanel(new GridBagLayout());
        subPanel.setBorder(BorderFactory.createTitledBorder("Site Map Config"));
        routePanel.setBorder(BorderFactory.createTitledBorder("Site Map"));
        routePanel.add(subPanel,BorderLayout.BEFORE_FIRST_LINE);
        addHttpService(subPanel);
        addImportRoutesToSiteMapButton(subPanel);
        addRouteTable(routePanel);
        panel.add(routePanel,BorderLayout.CENTER);

        return panel;
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
        Optional<Routes> routes = reader.getRoutes(orgID, appID);
        if (routes.isPresent()) {
            Map<Route,Future<Optional<RouteCoverage>>> routeFutureMap = new HashMap<>();
            for (Route route : routes.get().getRoutes()) {
                String routeID = route.getRoute_hash();
                routeFutureMap.put(route, reader.getCoverageForTrace(orgID, appID, routeID));
            }
            for(Route route : routeFutureMap.keySet()) {
                Optional<RouteCoverage> result = routeFutureMap.get(route).get();
                routeCoverageMap.put(route,result);
                if(result.isPresent() ) {
                    for(RouteCoverageObservationResource observationResource : result.get().getObservations() ) {
                        routeTableModel.addRow(new Object[]{observationResource.getUrl(),observationResource.getVerb(),false});
                    }
                }
            }
        }
        List<Future<HttpRequestResponse>> futureReqResponses = new ArrayList<>();
        for (Trace trace : traces) {
            futureReqResponses.add(reader.getHttpRequest(orgID,trace.getUuid()));
        }
        for(Future<HttpRequestResponse> futureReqRes : futureReqResponses) {
            HttpRequestResponse hreqRes = futureReqRes.get();
            vulnRequests.add(hreqRes);
            if(hreqRes.getHttpRequest()!=null) {
                String text = hreqRes.getHttpRequest().getText();
                if(text.contains(" ")&&text.contains(" HTTP")) {
                    String verb = text.split(" ")[0];
                    String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                    routeTableModel.addRow(new Object[]{url, verb, true});
                }
            }
        }
    }


    /**
     * updates the trace table with vulnerabilities
     * @param orgID the Organization ID
     * @param appID the Application ID
     * @param reader configured TSReader
     * @throws IOException
     */
    private void updateTraceTable(String orgID, String appID, TSReader reader) throws IOException {
        traces = reader.getTraces(orgID,appID);
        DefaultTableModel tableModel = (DefaultTableModel) traceTable.getModel();
        traces.forEach(trace -> tableModel.addRow(new Object[]{trace.getTitle(),trace.getRule(),trace.getSeverity()}));
        traceTable.updateUI();
    }


    /**
     * Update button, updates the trace and route tables.
     * @param appConfig
     */
    private void addUpdateButton(JPanel appConfig) {
        updateButton = new JButton("Update");
        updateButton.setEnabled(false);
        updateButton.addActionListener(e -> {
            if (credsFile != null) {
                try {
                    clearRouteTable();
                    routeCoverageMap.clear();
                    vulnRequests.clear();
                    Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                    if (creds.isPresent()) {
                        String orgID = orgsCombo.getSelectedItem().toString();
                        String appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                        TSReader reader = new TSReader(creds.get(), logger);
                        updateTraceTable(orgID, appID, reader);
                        updateRouteTable(orgID, appID, reader);
                    }
                } catch (IOException | InterruptedException | ExecutionException ex) {
                    logger.logException("Error occurred while updating tables",ex);
                    throw new RuntimeException(ex);
                }
                importRoutesButton.setEnabled(true);
            }
        });
        appConfig.add(updateButton);
    }


    private void addHttpService(JPanel panel) {
        protocolCombo = new JComboBox<>();
        protocolCombo.addItem("http");
        protocolCombo.addItem("https");
        panel.add(protocolCombo);
        hostNameField = new TextField();
        hostNameField.setText("localhost");
        portNumberField = new TextField();
        portNumberField.setText("8080");
        panel.add(hostNameField);
        panel.add(portNumberField);
    }

    /**
     * Clears the Route Table, called when a new application is selected in the application drop down.
     */
    private void clearRouteTable() {
        if(routeTable!=null) {
            DefaultTableModel tableModel = (DefaultTableModel) routeTable.getModel();
            tableModel.setRowCount(0);
        }
    }

    /**
     * Adds the Route Table to the UI
     * @param panel
     */
    private void addRouteTable(JPanel panel) {
        routeTableModel = new DefaultTableModel();
        String[] colNames = {"Path", "Verb", "From Vuln"};
        routeTableModel.setColumnIdentifiers(colNames);
        routeTable = new JTable();
        routeTable.setModel(routeTableModel);
        routeTable.getColumnModel().getColumn(0).setPreferredWidth(300);
        routeTable.getColumnModel().getColumn(1).setMaxWidth(50);
        routeTable.getColumnModel().getColumn(2).setMaxWidth(100);
        JScrollPane scrollPane = new JScrollPane(routeTable);
        routeTable.setFillsViewportHeight(true);
        panel.add(scrollPane,BorderLayout.CENTER);
    }

    /**
     * Adds the Import Route to Site Map Button. When selected, this takes the contents of the Route table, converts it
     * into the format expected by Burp and imports it into the Burp Site Map.
     * @param panel
     */
    private void addImportRoutesToSiteMapButton(JPanel panel) {
        importRoutesButton = new JButton("Import Routes To Site Map");
        importRoutesButton.setEnabled(false);
        panel.add(importRoutesButton);
        importRoutesButton.addActionListener(e -> {
            if(credsFile!= null) {
                try {
                    Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                    if(creds.isPresent()) {
                        String orgID = orgsCombo.getSelectedItem().toString();
                        String appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                        TSReader reader = new TSReader(creds.get(),logger);
                        Optional<Routes> routes = reader.getRoutes(orgID,appID);
                        RequestResponseGenerator generator = new RequestResponseGenerator();
                        HttpService service = new HttpService(hostNameField.getText(),
                                Integer.parseInt(portNumberField.getText()),
                                protocolCombo.getSelectedItem().toString()
                        );
                        if(routes.isPresent()) {
                            for(Route route : routeCoverageMap.keySet()) {
                                Optional<RouteCoverage> routeCoverage = routeCoverageMap.get(route);
                                if(routeCoverage.isPresent()) {
                                    for(RouteCoverageObservationResource r : routeCoverage.get().getObservations()) {
                                        callbacks.addToSiteMap(generator.getReqResForRouteCoverage(r,service));
                                    }
                                }
                            }
                        }
                        for (HttpRequestResponse hreqRes : vulnRequests) {
                            Optional<IHttpRequestResponse> requestResponse = generator.getReqResForTrace(hreqRes,service);
                            requestResponse.ifPresent(callbacks::addToSiteMap);
                        }
                    }
                } catch (IOException ex) {
                    logger.logException("Error occurred importing site map",ex);
                    throw new RuntimeException(ex);
                }
            }
        });

    }

    /**
     * Clears the Trace Table. This is called when a new Application is selected in the Application drop down.
     */
    private void clearTraceTable() {
        if(traceTable!=null) {
            DefaultTableModel tableModel = (DefaultTableModel) traceTable.getModel();
            tableModel.setRowCount(0);
        }
    }

    /**
     * Adds the Trace Table to the UI
     * @param panel
     */
    private void addTraceTable(JPanel panel) {
        String[] colNames = {"Name","Rule","Severity"};
        DefaultTableModel model = new DefaultTableModel();
        model.setColumnIdentifiers(colNames);
        traceTable = new JTable();
        traceTable.setModel(model);
        JScrollPane scrollPane = new JScrollPane(traceTable);
        traceTable.setFillsViewportHeight(true);
        panel.add(scrollPane,BorderLayout.CENTER);
    }

    /**
     * Adds the Application Down down to the UI.
     * When a change is made to the down, it clears the contents of the Route and Trace tables.
     * @param panel
     * @param gbc
     */
    private void addApplicationDropDown(JPanel panel,GridBagConstraints gbc) {
        appButton = new JButton("Refresh Application Names");
        appButton.setEnabled(false);
        appCombo = new JComboBox<>();
        appCombo.addActionListener(e -> {
            clearTraceTable();
            clearRouteTable();
        });
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 4;
        panel.add(appButton,gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 5;
        panel.add(appCombo,gbc);
        appButton.addActionListener(e -> refreshApplications());
    }

    /**
     * Logic that is called when the "Refresh Applications" Button is pressed.
     * This calls TS to get an updated list of applications for the specified Org.
     */
    private static void refreshApplications() {
        if (credsFile != null) {
            try {
                Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                appCombo.removeAllItems();
                appNameIDMap.clear();
                if (creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get(),logger);
                    List<Application> applications = reader.getApplications(Objects.requireNonNull(orgsCombo.getSelectedItem()).toString());
                    applications.forEach(application -> appNameIDMap.put(application.getName(), application.getId()));
                    applications.stream().map(Application::getName).forEach(nme -> appCombo.addItem(nme));
                }
            } catch (IOException ex) {
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
        orgIdButton = new JButton("Refresh Org IDS");
        orgIdButton.setEnabled(false);
        orgsCombo = new JComboBox<>();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(orgIdButton,gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 3;
        panel.add(orgsCombo,gbc);
        orgIdButton.addActionListener(e -> refreshOrgIDS());
    }

    /**
     * Logic that is called when the "Refresh Org IDS" Button is pressed.
     * This calls TS to get an updated list of organizations.
     */
    private static void refreshOrgIDS() {
        if(credsFile!= null) {
            try {
                Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                orgsCombo.removeAllItems();
                if(creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get(),logger);
                    List<String> orgIds = reader.getOrgs().stream().map(Organization::getOrgUuid).collect(Collectors.toList());
                    orgIds.forEach(item->orgsCombo.addItem(item));
                }
            } catch (IOException ex) {
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
    private static void createFileChooser(final JPanel panel){
        JButton button = new JButton("Select Creds File");
        final JLabel label = new JLabel();
        label.setText("Select Config File");
        button.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            int option = fileChooser.showOpenDialog(panel);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                credsFile = file;
                if(credsFile!=null) {
                    logger.logMessage("Creds File Selected : " + credsFile);
                } else {
                    logger.logMessage("Creds File is null");
                }
                label.setText("Selected: " + credsFile.getName());
                enableButtons();
                refreshOrgIDS();
                refreshApplications();
            }else{
                label.setText("Open command canceled");
            }
        });
        panel.add(button);
        panel.add(label);
    }

    /**
     * Enables the org, app and update buttons.
     */
    private static void enableButtons() {
        orgIdButton.setEnabled(true);
        appButton.setEnabled(true);
        updateButton.setEnabled(true);
    }
}
