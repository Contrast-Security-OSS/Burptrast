package burp;

import com.contrast.Logger;
import com.contrast.SortByAppNameComparator;
import com.contrast.SortByLastSeenComparator;
import com.contrast.SortType;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.YamlReader;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.exceptions.ContrastException;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Organization;
import com.contrastsecurity.models.Story;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;

import javax.swing.*;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class ContrastTab implements ITab{




    public ContrastTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        logger = new Logger( new PrintWriter(callbacks.getStdout(), true),
                new PrintWriter(callbacks.getStderr(), true)
        );
    }

    public static String[] ROUTE_TABLE_COL_NAMES = {"Selected","Path", "Verb", "From Vuln","Last Exercised"};

    public static String[] TRACE_TABLE_COL_NAMES = {"Name","Rule","Severity"};



    private final IBurpExtenderCallbacks callbacks;
    private static Logger logger;

    private static final DataModel dataModel = new DataModel();



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
        addApplicationSortRadioButtons(appConfig,gbc);
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
                dataModel.getRouteCoverageMap().put(route,result);
                if(result.isPresent() ) {
                    for(RouteCoverageObservationResource observationResource : result.get().getObservations() ) {
                        dataModel.getRouteTableModel().addRow(new Object[]{true,observationResource.getUrl(),observationResource.getVerb(),false,getLastExercisedDate(route)});
                    }
                }
            }
        }
        List<Future<TraceIDDecoractedHttpRequestResponse>> futureReqResponses = new ArrayList<>();
        for (Trace trace : dataModel.getTraces()) {
            futureReqResponses.add(reader.getHttpRequest(orgID,trace.getUuid()));
        }
        for(Future<TraceIDDecoractedHttpRequestResponse> futureReqRes : futureReqResponses) {
            HttpRequestResponse hreqRes = futureReqRes.get().getRequestResponse();
            dataModel.getVulnRequests().add(futureReqRes.get());
            Optional<VulnTableResult> vulnTableResult = getVulnTableResult(hreqRes);
            if(vulnTableResult.isPresent()) {
                dataModel.getRouteTableModel().addRow(new Object[]{true,vulnTableResult.get().getUrl(), vulnTableResult.get().getVerb(), true,""});

            }
            if(hreqRes.getHttpRequest()!=null) {
                String text = hreqRes.getHttpRequest().getText();
                if(text.contains(" ")&&text.contains(" HTTP")) {
                    String verb = text.split(" ")[0];
                    String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                }
            }
        }
        for(PathTracePair pathTracePair : getPathsFromNonRequestVulns(orgID,reader)) {
            String path = pathTracePair.getPath();
            boolean isFound = false;
            for( int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
                String tablePath = dataModel.getRouteTableModel().getValueAt(i,1).toString();
                if(tablePath.equals(path)) {
                    isFound = true;
                    break;
                }
            }
            if(!isFound) {
                dataModel.getRouteTableModel().addRow(new Object[]{true,path, "", true,""});
            }
            addNonRequestVulnToMap(path,pathTracePair.getTrace());
        }

    }

    private void addNonRequestVulnToMap(String path,Trace trace) {
        if(dataModel.getNonRequestPathVulnMap().containsKey(path)) {
            dataModel.getNonRequestPathVulnMap().get(path).add(trace);
        } else {
            Set<Trace> traceSet = new HashSet<>();
            traceSet.add(trace);
            dataModel.getNonRequestPathVulnMap().put(path,traceSet);
        }
    }


    private Optional<VulnTableResult> getVulnTableResult(HttpRequestResponse hreqRes) {
        if(hreqRes.getHttpRequest()!=null) {
            String text = hreqRes.getHttpRequest().getText();
            if(text.contains(" ")&&text.contains(" HTTP")) {
                String verb = text.split(" ")[0];
                String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                return Optional.of(new VulnTableResult(url,verb));
            }
        }
        return Optional.empty();
    }


    private String getLastExercisedDate(Route route) {
        Long lastExercised = route.getExercised();
        if(lastExercised==null) {
            return "";
        } else {
            String dateString =  new Date(lastExercised).toString();
            dataModel.getFormattedDateMap().put(dateString,lastExercised);
            return dateString;
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
        dataModel.getTraces().clear();
        dataModel.getTraces().addAll(reader.getTraces(orgID,appID));
        reader.getTraces(orgID,appID).forEach(trace -> dataModel.getTraceTableModel().addRow(new Object[]{trace.getTitle(),trace.getRule(),trace.getSeverity()}));
        Components.getTraceTable().updateUI();
    }


    /**
     * Update button, updates the trace and route tables.
     * @param appConfig
     */
    private void addUpdateButton(JPanel appConfig) {
        Components.setUpdateButton(new JButton("Update"));
        Components.getUpdateButton().setEnabled(false);
        Components.getUpdateButton().addActionListener(e -> {
            if (dataModel.getCredsFile() != null) {
                try {
                    dataModel.clearData();
                    dataModel.clearTraceTable();
                    dataModel.clearRouteTable();
                    Optional<TSCreds> tsCreds = getCreds();
                    if (tsCreds.isPresent()) {
                        String orgID = Components.getOrgsCombo().getSelectedItem().toString();
                        String appID = dataModel.getAppNameIDMap().get(Components.getAppCombo().getSelectedItem().toString());
                        TSReader reader = new TSReader(dataModel.getCredentials().get(), logger,dataModel);
                        updateTraceTable(orgID, appID, reader);
                        updateRouteTable(orgID, appID, reader);
                    }
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
        Components.setProtocolCombo(new JComboBox<>());
        Components.getProtocolCombo().addItem("http");
        Components.getProtocolCombo().addItem("https");
        panel.add(Components.getProtocolCombo());
        Components.setHostNameField(new TextField());
        Components.getHostNameField().setText("localhost");
        Components.setPortNumberField(new TextField());
        Components.getPortNumberField().setText("8080");
        Components.setAppContextField(new TextField("",20));
        Components.setPathLabel(new JLabel());
        Components.getPathLabel().setText(getPathString());
        addPathUpdater();
        panel.add(Components.getHostNameField());
        panel.add(Components.getPortNumberField());
        panel.add(Components.getAppContextField());
        JPanel subPanel = new JPanel();
        subPanel.setBorder(BorderFactory.createTitledBorder("URL"));
        subPanel.add(Components.getPathLabel());
        panel.add(subPanel);

    }

    private void addPathUpdater() {
        Components.getProtocolCombo().addActionListener(e -> Components.getPathLabel().setText(getPathString()));
        Components.getHostNameField().addActionListener(e -> Components.getPathLabel().setText(getPathString()));
        Components.getPortNumberField().addActionListener(e -> Components.getPathLabel().setText(getPathString()));
        Components.getAppContextField().addActionListener(e -> Components.getPathLabel().setText(getPathString()));
    }

    private String getPathString() {
        StringBuilder msg = new StringBuilder();
        msg.append(Components.getProtocolCombo().getSelectedItem())
                .append("://")
                .append(Components.getHostNameField().getText())
                .append(":")
                .append(Components.getPortNumberField().getText())
                .append(Components.getAppContextField().getText());
        return msg.toString();
    }



    /**
     * Adds the Route Table to the UI
     * @param panel
     */
    private void addRouteTable(JPanel panel) {
        dataModel.setRouteTableModel(new NonEditableTableModel());
        dataModel.getRouteTableModel().setColumnIdentifiers(ROUTE_TABLE_COL_NAMES);
        Components.setRouteTable(new RouteTable());
        Components.getRouteTable().setModel(dataModel.getRouteTableModel());
        JCheckBox selectedCheckBox =  new JCheckBox("Selected");
        selectedCheckBox.setSelected(true);
        selectedCheckBox.addActionListener(e -> {
            JCheckBox box = (JCheckBox) e.getSource();
            Boolean isSelected = box.isSelected();
            for( int i = 0; i<dataModel.getRouteTableModel().getRowCount() ;i++) {
                dataModel.getRouteTableModel().setValueAt(isSelected,i,0);
            }
        });
        Components.getRouteTable().getColumnModel().getColumn(0).setHeaderRenderer(new EditableHeaderRenderer(selectedCheckBox));
        Components.getRouteTable().getColumnModel().getColumn(0).setMaxWidth(80);
        Components.getRouteTable().getColumnModel().getColumn(0).setMinWidth(80);
        Components.getRouteTable().getColumnModel().getColumn(0).setPreferredWidth(80);

        Components.getRouteTable().getColumnModel().getColumn(1).setPreferredWidth(300);
        Components.getRouteTable().getColumnModel().getColumn(2).setMaxWidth(50);
        Components.getRouteTable().getColumnModel().getColumn(3).setMaxWidth(100);
        Components.getRouteTable().getColumnModel().getColumn(4).setMaxWidth(250);
        Components.getRouteTable().getColumnModel().getColumn(4).setPreferredWidth(250);

        JScrollPane scrollPane = new JScrollPane(Components.getRouteTable());
        Components.getRouteTable().setFillsViewportHeight(true);
        TableRowSorter<TableModel> sorter
                = new TableRowSorter<>(Components.getRouteTable().getModel());
        sorter.setComparator(4, new RouteTableComparator(dataModel));
        Components.getRouteTable().setRowSorter(sorter);
        panel.add(scrollPane,BorderLayout.CENTER);

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
            new SiteMapImporter(dataModel,callbacks,logger,new TSReader(dataModel.getCredentials().get(),logger,dataModel)).importSiteMapToBurp(
                    Components.getOrgsCombo().getSelectedItem().toString(),
                    Components.getAppCombo().getSelectedItem().toString(),
                    Components.getHostNameField().getText(),
                    Integer.parseInt(Components.getPortNumberField().getText()),
                    Components.getProtocolCombo().getSelectedItem().toString(),
                    Components.getAppContextField().getText()
                    );
        });

    }


    /**
     * Adds the Trace Table to the UI
     * @param panel
     */
    private void addTraceTable(JPanel panel) {
        dataModel.setTraceTableModel(new NonEditableTableModel());
        dataModel.getTraceTableModel().setColumnIdentifiers(TRACE_TABLE_COL_NAMES);
        Components.setTraceTable( new JTable());
        Components.getTraceTable().setModel(dataModel.getTraceTableModel());

        JScrollPane scrollPane = new JScrollPane(Components.getTraceTable());
        Components.getTraceTable().setFillsViewportHeight(true);
        panel.add(scrollPane,BorderLayout.CENTER);
        TableRowSorter<TableModel> sorter
                = new TableRowSorter<>(Components.getTraceTable().getModel());
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
        if (dataModel.getCredsFile() != null) {
            try {
                Optional<TSCreds> creds = getCreds();
                Components.getAppCombo().removeAllItems();
                dataModel.getAppNameIDMap().clear();
                if (creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get(),logger,dataModel);
                    List<Application> applications = reader.getApplications(Objects.requireNonNull(Components.getOrgsCombo().getSelectedItem()).toString());
                    applications.forEach(application -> dataModel.getAppNameIDMap().put(application.getName(), application.getId()));
                    if(dataModel.getSortType().equals(SortType.SORT_BY_NAME)) {
                        applications.sort(new SortByAppNameComparator());
                    } else {
                        applications.sort(new SortByLastSeenComparator());
                    }
                    applications.forEach(application -> Components.getAppCombo().addItem(application.getName()));
                }
            } catch (IOException|ContrastException ex) {
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
        Components.getOrgIdButton().addActionListener(e -> refreshOrgIDS());
    }

    /**
     * Logic that is called when the "Refresh Org IDS" Button is pressed.
     * This calls TS to get an updated list of organizations.
     */
    private void refreshOrgIDS() {
        if(dataModel.getCredsFile()!= null) {
            try {
                Optional<TSCreds> creds = getCreds();
                Components.getOrgsCombo().removeAllItems();
                if(creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get(),logger,dataModel);
                    List<String> orgIds = reader.getOrgs().stream().map(Organization::getOrgUuid).collect(Collectors.toList());
                    orgIds.forEach(item->Components.getOrgsCombo().addItem(item));
                }
            } catch (IOException|ContrastException ex) {
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
    private void createFileChooser(final JPanel panel){
        JButton button = new JButton("Select Creds File");
        final JLabel label = new JLabel();
        label.setText("Select Config File");
        button.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            int option = fileChooser.showOpenDialog(panel);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                dataModel.setCredsFile(file);
                if(dataModel.getCredsFile()!=null) {
                    logger.logMessage("Creds File Selected : " + dataModel.getCredsFile());
                } else {
                    logger.logMessage("Creds File is null");
                }
                label.setText("Selected: " + dataModel.getCredsFile().getName());
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

    private Optional<TSCreds> getCreds() throws IOException {
        if(!dataModel.getCredentials().isPresent()) {
            dataModel.setCredentials(new YamlReader().parseContrastYaml(new File(dataModel.getCredsFile().getAbsolutePath())));
            return dataModel.getCredentials();
        } else {
            return dataModel.getCredentials();
        }
    }

    /**
     * Enables the org, app and update buttons.
     */
    private void enableButtons() {
        Components.getOrgIdButton().setEnabled(true);
        Components.getAppButton().setEnabled(true);
        Components.getUpdateButton().setEnabled(true);
        Components.getSortByAppNameRadio().setEnabled(true);
        Components.getSortByLastSeenRadio().setEnabled(true);
    }


    private StoryResponse getStoryResponse(String orgID, String traceID,TSReader reader) throws IOException {
        if(!dataModel.getTraceIDStoryMap().containsKey(traceID)) {
            StoryResponse response = reader.getStory(orgID,traceID);
            dataModel.getTraceIDStoryMap().put(traceID,response);
        }
        return dataModel.getTraceIDStoryMap().get(traceID);
    }

    private List<PathTracePair> getPathsFromNonRequestVulns(String orgID,TSReader reader) throws IOException {
        List<PathTracePair> paths = new ArrayList<>();
        for (Trace trace : dataModel.getTraces()) {
            StoryResponse response = getStoryResponse(orgID, trace.getUuid(), reader);
            Story story = response.getStory();
            if (story.getChapters() != null) {
                Optional<Chapter> chapter = story.getChapters().stream().filter(chp -> "properties".equals(chp.getType())).findFirst();
                if (chapter.isPresent() && chapter.get().getPropertyResources() != null && !chapter.get().getPropertyResources().isEmpty()) {
                    paths.add(new PathTracePair(chapter.get().getPropertyResources().get(0).getName(), trace));
                }
            }
        }
        return paths;
    }

}



