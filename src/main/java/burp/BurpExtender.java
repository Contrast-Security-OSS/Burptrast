package burp;


public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Burptrast Security");
        callbacks.addSuiteTab(new ContrastTab(callbacks));

    }

}
