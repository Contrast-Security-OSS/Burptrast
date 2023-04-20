package burp;

import com.contrast.Logger;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

public class ParentTab implements ITab{


    private final IBurpExtenderCallbacks callbacks;

    public ParentTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public String getTabCaption() {
        return "Burptrast";
    }

    @Override
    public Component getUiComponent() {
        Logger logger = new Logger( new PrintWriter(callbacks.getStdout(), true),
                new PrintWriter(callbacks.getStderr(), true)
        );
        DataModel dm = new DataModel();
        JTabbedPane tabbedPane = new JTabbedPane();
        CredentialsTab credentialsTab = new CredentialsTab(callbacks,dm,logger);
        ContrastTab contrastTab = new ContrastTab(callbacks,dm,logger);
        tabbedPane.addTab("Credentials",credentialsTab.getUiComponent());
        tabbedPane.addTab("Contrast",contrastTab.getUiComponent());
        return tabbedPane;
    }
}
