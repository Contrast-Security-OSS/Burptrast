package burp;

import java.awt.*;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Burptrast Security Extension");
        callbacks.addSuiteTab(new ContrastTab(callbacks));


    }




}
