package burp;

import com.contrast.HttpService;
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
import com.contrastsecurity.models.Trace;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.awt.GridBagConstraints.LINE_START;

public class ContrastTab implements ITab{

    private final IBurpExtenderCallbacks callbacks;



    public ContrastTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    private TextField portNumberField;

    private TextField hostNameField;

    private static JComboBox<String> protocolCombo;

    private static JComboBox<String> orgsCombo;

    private static JComboBox<String> appCombo;

   private static JButton routeButton;

    private static JButton orgIdButton;

    private static JButton appButton;

    private static JButton tableButton;

    private static JButton listRoutesButton;


    private static Map<Route,Optional<RouteCoverage>> routeCoverageMap = new HashMap<>();

    private static List<HttpRequestResponse> vulnRequests = new ArrayList<>();

    private static File credsFile = null;

    private static Map<String,String> appNameIDMap = new HashMap<>();

    private List<Trace> traces = new ArrayList<>();

    @Override
    public String getTabCaption() {
        return "Burptrast Security";
    }

    @Override
    public Component getUiComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setName("con");
        GridBagConstraints gbc = new GridBagConstraints();
        JPanel firstLine = new JPanel(new GridBagLayout());

        JPanel configPanel = new JPanel();
        configPanel.setBorder( BorderFactory.createTitledBorder("Credentials"));
        firstLine.add(configPanel);
        createFileChooser(configPanel);


        JPanel appConfig = new JPanel();
        appConfig.setBorder(BorderFactory.createTitledBorder("Application Configuration"));
        addOrgsDropDown(appConfig,gbc);
        addApplicationDropDown(appConfig,gbc);
        firstLine.add(appConfig);

        panel.add(firstLine,BorderLayout.BEFORE_FIRST_LINE);

        JPanel tracePanel = new JPanel(new BorderLayout());
        JPanel subTracePanel = new JPanel(new GridBagLayout());
        subTracePanel.setBorder(BorderFactory.createTitledBorder("Trace Config"));
        tracePanel.setBorder(BorderFactory.createTitledBorder("Trace Table"));
        tracePanel.add(subTracePanel,BorderLayout.BEFORE_FIRST_LINE);
        addTraceTable(tracePanel,subTracePanel);
        panel.add(tracePanel,BorderLayout.BEFORE_LINE_BEGINS);



        JPanel routePanel = new JPanel(new BorderLayout());
        JPanel subPanel = new JPanel(new GridBagLayout());
        subPanel.setBorder(BorderFactory.createTitledBorder("Site Map Config"));
        routePanel.setBorder(BorderFactory.createTitledBorder("Site Map"));
        routePanel.add(subPanel,BorderLayout.BEFORE_FIRST_LINE);
        listRoutesButton = new JButton("List Routes");
        listRoutesButton.setEnabled(false);
        subPanel.add(listRoutesButton);
        addHttpService(subPanel);
        addAddRoutes(subPanel);
        addRouteTable(routePanel,subPanel,listRoutesButton);

        panel.add(routePanel,BorderLayout.CENTER);

        return panel;
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

    private void addRouteTable(JPanel panel,JPanel subPanel,JButton listRoutesButton) {

        DefaultTableModel model = new DefaultTableModel();
        String[] colNames = {"Path", "Verb", "From Vuln"};
        model.setColumnIdentifiers(colNames);
        JTable table = new JTable();
        table.setModel(model);
        table.getColumnModel().getColumn(0).setPreferredWidth(300);
        table.getColumnModel().getColumn(1).setMaxWidth(50);
        table.getColumnModel().getColumn(2).setMaxWidth(100);

        listRoutesButton.addActionListener(e -> {
            if (credsFile != null) {
                try {
                    model.setRowCount(0);
                    routeCoverageMap.clear();
                    vulnRequests.clear();
                    Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                    if (creds.isPresent()) {
                        String orgID = orgsCombo.getSelectedItem().toString();
                        String appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                        TSReader reader = new TSReader(creds.get());
                        Optional<Routes> routes = reader.getRoutes(orgID, appID);
                        if (routes.isPresent()) {
                            for (Route route : routes.get().getRoutes()) {
                                String routeID = route.getRoute_hash();
                                Optional<RouteCoverage> routeCoverage = reader.getCoverageForTrace(orgID, appID, routeID);
                                routeCoverageMap.put(route,routeCoverage);
                                if(routeCoverage.isPresent() ) {
                                    for(RouteCoverageObservationResource observationResource : routeCoverage.get().getObservations() ) {
                                        model.addRow(new Object[]{observationResource.getUrl(),observationResource.getVerb(),false});
                                    }
                                }
                            }
                        }
                        if(traces.isEmpty()) {
                            orgID = orgsCombo.getSelectedItem().toString();
                            appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                            traces = reader.getTraces(orgID,appID);
                        }
                        for (Trace trace : traces) {

                            HttpRequestResponse hreqRes = reader.getSDK().getHttpRequest(orgID, trace.getUuid());
                            vulnRequests.add(hreqRes);
                            if(hreqRes.getHttpRequest()!=null) {
                                String text = hreqRes.getHttpRequest().getText();
                                if(text.contains(" ")&&text.contains(" HTTP")) {
                                    String verb = text.split(" ")[0];
                                    String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                                    model.addRow(new Object[]{url, verb, true});
                                }
                            }
                        }
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                routeButton.setEnabled(true);
            }
        });
        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);
        panel.add(scrollPane,BorderLayout.CENTER);
    }

    private void addAddRoutes(JPanel panel) {
        routeButton = new JButton("Import Routes To Site Map");
        routeButton.setEnabled(false);
        panel.add(routeButton);
        routeButton.addActionListener(e -> {
            if(credsFile!= null) {
                try {
                    Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                    if(creds.isPresent()) {
                        String orgID = orgsCombo.getSelectedItem().toString();
                        String appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                        TSReader reader = new TSReader(creds.get());
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
                                        callbacks.addToSiteMap(generator.getReqRes(r,service));
                                    }
                                }
                            }
                        }
                        for (HttpRequestResponse hreqRes : vulnRequests) {
                            Optional<IHttpRequestResponse> requestResponse = generator.getReqRes(hreqRes,service);
                            requestResponse.ifPresent(callbacks::addToSiteMap);
                        }
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

            }
        });

    }

    private void addTraceTable(JPanel panel,JPanel subPanel) {
        String[] colNames = {"Name","Rule","Severity"};
        DefaultTableModel model = new DefaultTableModel();
        model.setColumnIdentifiers(colNames);
        JTable table = new JTable();
        table.setModel(model);
        tableButton = new JButton("Refresh Trace Table");
        tableButton.setEnabled(false);
        tableButton.addActionListener(e -> {
            if(credsFile!= null) {
                try {
                    Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                    if(creds.isPresent()) {
                        String orgID = orgsCombo.getSelectedItem().toString();
                        String appID = appNameIDMap.get(appCombo.getSelectedItem().toString());
                        TSReader reader = new TSReader(creds.get());
                        traces = reader.getTraces(orgID,appID);
                        DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
                        tableModel.setRowCount(0);
                        traces.forEach(trace -> tableModel.addRow(new Object[]{trace.getTitle(),trace.getRule(),trace.getSeverity()}));
                        table.updateUI();
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

            }
        });
        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);

        subPanel.add(tableButton);


        panel.add(scrollPane,BorderLayout.CENTER);
    }

    private void addApplicationDropDown(JPanel panel,GridBagConstraints gbc) {
        appButton = new JButton("Refresh Application Names");
        appButton.setEnabled(false);
        appCombo = new JComboBox<>();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 4;
        panel.add(appButton,gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 5;
        panel.add(appCombo,gbc);
        appButton.addActionListener(e -> performApplicationButton());
    }

    private static void performApplicationButton() {
        if (credsFile != null) {
            try {
                Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                appCombo.removeAllItems();
                appNameIDMap.clear();
                if (creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get());
                    List<Application> applications = reader.getApplications(orgsCombo.getSelectedItem().toString());
                    applications.forEach(application -> appNameIDMap.put(application.getName(), application.getId()));
                    applications.stream().map(app -> app.getName()).forEach(nme -> appCombo.addItem(nme));
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

        }
    }

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

    private static void refreshOrgIDS() {
        if(credsFile!= null) {
            try {
                Optional<TSCreds> creds = new YamlReader().parseContrastYaml(new File(credsFile.getAbsolutePath()));
                orgsCombo.removeAllItems();
                if(creds.isPresent()) {
                    TSReader reader = new TSReader(creds.get());
                    List<String> orgIds = reader.getOrgs().stream().map(org -> org.getOrgUuid()).collect(Collectors.toList());
                    orgIds.forEach(item->orgsCombo.addItem(item));
                    performApplicationButton();
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

        }
    }



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
                label.setText("Selected: " + file.getName());
                enableButtons();
                refreshOrgIDS();
                performApplicationButton();
            }else{
                label.setText("Open command canceled");
            }
        });
        panel.add(button);
        panel.add(label);
    }

    private static void enableButtons() {
        orgIdButton.setEnabled(true);
        appButton.setEnabled(true);
        tableButton.setEnabled(true);
        listRoutesButton.setEnabled(true);
    }
}
