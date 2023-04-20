package burp;


public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Burptrast Security");
        ParentTab parentTab = new ParentTab(callbacks);
        callbacks.addSuiteTab(parentTab);

    }

}
