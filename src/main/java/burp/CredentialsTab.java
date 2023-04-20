package burp;

import com.contrast.Logger;
import com.contrast.YamlReader;
import com.contrast.YamlWriter;
import com.contrast.threads.CredentialsRetrieverThread;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static burp.ContrastTab.enableButtons;
import static burp.ContrastTab.refreshOrgIDS;

public class CredentialsTab {

    private final IBurpExtenderCallbacks callbacks;
    private final DataModel dataModel;
    private final Logger logger;

    public CredentialsTab(IBurpExtenderCallbacks callbacks, DataModel dataModel, Logger logger) {
        this.callbacks = callbacks;
        this.dataModel = dataModel;
        this.logger = logger;
    }


    public Component getUiComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel firstLine = new JPanel(new BorderLayout());
        JPanel firstInner = new JPanel();
        JPanel secondLine = new JPanel(new BorderLayout());
        JPanel secondInner = new JPanel();
        JPanel credRetriever = new JPanel();
        credRetriever.setBorder( BorderFactory.createTitledBorder("Teamserver Credentials"));
        createCredRetriever(credRetriever);
        createCredSaveButton(credRetriever);
        firstInner.add(credRetriever);
        firstLine.add(firstInner);
        addStatusField(secondInner);
        // BurpTrast Credentials Panel
        JPanel configPanel = new JPanel();
        configPanel.setBorder( BorderFactory.createTitledBorder("Credential File"));
        createFileChooser(configPanel);
        secondInner.add(configPanel);
        secondLine.add(secondInner,BorderLayout.WEST);

        panel.add(secondLine, BorderLayout.PAGE_START);
        panel.add(firstLine,BorderLayout.LINE_START);
        return panel;
    }

    /**
     * Adds Status field to the UI, this is used to communicate the current status of Burptrast
     * @param secondLine
     */
    private void addStatusField(JPanel secondLine) {
        // Status Field
        JPanel statusPanel = new JPanel();
        Components.setCredentialsStatusPanel(statusPanel);
        statusPanel.setBorder(
                BorderFactory.createTitledBorder(null, "Status", TitledBorder.CENTER, TitledBorder.TOP, null,null));
        secondLine.add(statusPanel,BorderLayout.LINE_START);
        Components.setCredentialsStatusLabel(new JLabel(Status.AWAITING_CREDENTIALS.getStatus()));
        statusPanel.add(Components.getCredentialsStatusLabel());
    }

    /**
     * List of Teamserver URLs
     * @return
     */
    private List<String> getTSList() {
        return Arrays.asList(
                "",
                "https://ce.contrastsecurity.com/Contrast",
                "https://eval.contrastsecurity.com/Contrast",
                "https://security-research.contrastsecurity.com/Contrast",
                "https://apptwo.contrastsecurity.com/Contrast",
                "https://app.contrastsecurity.com/Contrast",
                "https://alpha.contrastsecurity.com/Contrast"
        );
    }

    private void createCredRetriever(JPanel credRetriever) {
        JTextField usernameField = new JTextField();
        JComboBox<String> teamserverURL = new JComboBox<>();
        teamserverURL.setEditable(true);
        getTSList().forEach(teamserverURL::addItem);
        teamserverURL.setToolTipText("Team Server URL : https://ce.contrastsecurity.com/Contrast");
        usernameField.setColumns(20);
        JPasswordField passwordField = new JPasswordField();
        passwordField.setColumns(20);
        credRetriever.add(new JLabel("Teamserver URL"));
        credRetriever.add(teamserverURL);
        credRetriever.add(new JLabel("Username"));
        credRetriever.add(usernameField);
        credRetriever.add(new JLabel("Password"));
        credRetriever.add(passwordField);
        JButton button = new JButton("Login");
        credRetriever.add(button);
        button.addActionListener(e -> {
            String username = usernameField.getText();
            String password = passwordField.getText();
            String tsURL = teamserverURL.getSelectedItem().toString();
            CredentialsRetrieverThread thread = new CredentialsRetrieverThread(callbacks,dataModel,logger,username,password,tsURL);
            thread.start();

        });
    }

    private void createCredSaveButton(JPanel credRetriever) {
        Components.setSaveCredsFile(new JButton("Save Credentials"));
        Components.getSaveCredsFile().setEnabled(false);
        credRetriever.add(Components.getSaveCredsFile());
        Components.getSaveCredsFile().addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int option = fileChooser.showSaveDialog(credRetriever);
            if(option == JFileChooser.APPROVE_OPTION){
                File file = fileChooser.getSelectedFile();
                if(file!=null) {
                    YamlWriter writer = new YamlWriter();
                    try {
                        writer.writeYamlFile(dataModel.getTsCreds(), file.toPath());
                    } catch (IOException ex) {
                        logger.logError("Unable to save Credentials to file : " + file.getAbsolutePath());
                        throw new RuntimeException(ex);
                    }
                }
            }
        });
    }

    /**
     * Adds the File Chooser to the UI
     * When a Creds file is selected, the refresh org, refresh app and update buttons are enabled.
     * Also the Org and App Drop downs are populated by calling TeamServer with the newly selected credentials.
     * @param panel
     */
    private void createFileChooser(final JPanel panel){
        Components.setCredsFile(new JButton("Select Creds File"));
        final JLabel label = new JLabel();
        label.setText("Select Config File");
        Components.getCredsFile().addActionListener(e -> {
            StatusUpdater.updateStatus(Status.LOADING,dataModel);
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
                dataModel.getTsCreds().clear();
                try {
                    dataModel.getTsCreds().addAll(new YamlReader().parseContrastYaml(dataModel.getCredsFile()));
                    StatusUpdater.updateStatus(Status.READY,dataModel);
                    Components.getCredsFile().setEnabled(true);


                } catch (IOException ex) {
                    StatusUpdater.updateStatus(Status.ERROR,dataModel);
                    Components.getCredentialsStatusLabel().setText(Status.ERROR.getStatus());
                    JOptionPane.showMessageDialog(null, ex+
                            "\nSee Error log under extensions -> Errors for further details.");
                    logger.logException("Error occurred while refreshing org list",ex);
                    throw new RuntimeException(ex);
                }
                enableButtons();
                refreshOrgIDS(callbacks);
            }else{
                StatusUpdater.updateStatus(Status.AWAITING_CREDENTIALS,dataModel);
                label.setText("Open command canceled");
            }
        });
        panel.add(Components.getCredsFile());
        panel.add(label);
    }




}
