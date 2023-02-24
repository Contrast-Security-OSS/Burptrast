package burp;

import java.awt.*;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TestableCallBack implements IBurpExtenderCallbacks {

    private List<IHttpRequestResponse> requestResponses = new ArrayList<>();

    private List<IScanIssue> scanIssues = new ArrayList<>();

    public List<IScanIssue> getScanIssues() {
        return scanIssues;
    }

    public List<IHttpRequestResponse> getRequestResponses() {
        return requestResponses;
    }

    @Override
    public void setExtensionName(String name) {

    }

    @Override
    public IExtensionHelpers getHelpers() {
        return null;
    }

    @Override
    public OutputStream getStdout() {
        return System.out;
    }

    @Override
    public OutputStream getStderr() {
        return System.err;
    }

    @Override
    public void printOutput(String output) {

    }

    @Override
    public void printError(String error) {

    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener listener) {

    }

    @Override
    public List<IExtensionStateListener> getExtensionStateListeners() {
        return null;
    }

    @Override
    public void removeExtensionStateListener(IExtensionStateListener listener) {

    }

    @Override
    public void registerHttpListener(IHttpListener listener) {

    }

    @Override
    public List<IHttpListener> getHttpListeners() {
        return null;
    }

    @Override
    public void removeHttpListener(IHttpListener listener) {

    }

    @Override
    public void registerProxyListener(IProxyListener listener) {

    }

    @Override
    public List<IProxyListener> getProxyListeners() {
        return null;
    }

    @Override
    public void removeProxyListener(IProxyListener listener) {

    }

    @Override
    public void registerScannerListener(IScannerListener listener) {

    }

    @Override
    public List<IScannerListener> getScannerListeners() {
        return null;
    }

    @Override
    public void removeScannerListener(IScannerListener listener) {

    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener listener) {

    }

    @Override
    public List<IScopeChangeListener> getScopeChangeListeners() {
        return null;
    }

    @Override
    public void removeScopeChangeListener(IScopeChangeListener listener) {

    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory factory) {

    }

    @Override
    public List<IContextMenuFactory> getContextMenuFactories() {
        return null;
    }

    @Override
    public void removeContextMenuFactory(IContextMenuFactory factory) {

    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory factory) {

    }

    @Override
    public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
        return null;
    }

    @Override
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory factory) {

    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {

    }

    @Override
    public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
        return null;
    }

    @Override
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {

    }

    @Override
    public void registerScannerCheck(IScannerCheck check) {

    }

    @Override
    public List<IScannerCheck> getScannerChecks() {
        return null;
    }

    @Override
    public void removeScannerCheck(IScannerCheck check) {

    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {

    }

    @Override
    public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
        return null;
    }

    @Override
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {

    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {

    }

    @Override
    public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
        return null;
    }

    @Override
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {

    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction action) {

    }

    @Override
    public List<ISessionHandlingAction> getSessionHandlingActions() {
        return null;
    }

    @Override
    public void removeSessionHandlingAction(ISessionHandlingAction action) {

    }

    @Override
    public void unloadExtension() {

    }

    @Override
    public void addSuiteTab(ITab tab) {

    }

    @Override
    public void removeSuiteTab(ITab tab) {

    }

    @Override
    public void customizeUiComponent(Component component) {

    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable) {
        return null;
    }

    @Override
    public String[] getCommandLineArguments() {
        return new String[0];
    }

    @Override
    public void saveExtensionSetting(String name, String value) {

    }

    @Override
    public String loadExtensionSetting(String name) {
        return null;
    }

    @Override
    public ITextEditor createTextEditor() {
        return null;
    }

    @Override
    public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {

    }

    @Override
    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {

    }

    @Override
    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request, List<int[]> payloadPositionOffsets) {

    }

    @Override
    public void sendToComparer(byte[] data) {

    }

    @Override
    public void sendToSpider(URL url) {

    }

    @Override
    public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request) {
        return null;
    }

    @Override
    public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request, List<int[]> insertionPointOffsets) {
        return null;
    }

    @Override
    public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {

    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) {
        return null;
    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request, boolean forceHttp1) {
        return null;
    }

    @Override
    public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request, boolean forceHttp1) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body, boolean forceHttp2) {
        return new byte[0];
    }

    @Override
    public byte[] makeHttp2Request(IHttpService httpService, List<IHttpHeader> headers, byte[] body, boolean forceHttp2, String connectionIdentifier) {
        return new byte[0];
    }

    @Override
    public boolean isInScope(URL url) {
        return false;
    }

    @Override
    public void includeInScope(URL url) {

    }

    @Override
    public void excludeFromScope(URL url) {

    }

    @Override
    public void issueAlert(String message) {

    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String urlPrefix) {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IScanIssue[] getScanIssues(String urlPrefix) {
        return new IScanIssue[0];
    }

    @Override
    public void generateScanReport(String format, IScanIssue[] issues, File file) {

    }

    @Override
    public List<ICookie> getCookieJarContents() {
        return null;
    }

    @Override
    public void updateCookieJar(ICookie cookie) {

    }

    @Override
    public void addToSiteMap(IHttpRequestResponse item) {
        requestResponses.add(item);
    }

    @Override
    public void restoreState(File file) {

    }

    @Override
    public void saveState(File file) {

    }

    @Override
    public Map<String, String> saveConfig() {
        return null;
    }

    @Override
    public void loadConfig(Map<String, String> config) {

    }

    @Override
    public String saveConfigAsJson(String... configPaths) {
        return null;
    }

    @Override
    public void loadConfigFromJson(String config) {

    }

    @Override
    public void setProxyInterceptionEnabled(boolean enabled) {

    }

    @Override
    public String[] getBurpVersion() {
        return new String[0];
    }

    @Override
    public String getExtensionFilename() {
        return null;
    }

    @Override
    public boolean isExtensionBapp() {
        return false;
    }

    @Override
    public void exitSuite(boolean promptUser) {

    }

    @Override
    public ITempFile saveToTempFile(byte[] buffer) {
        return null;
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse httpRequestResponse, List<int[]> requestMarkers, List<int[]> responseMarkers) {
        return null;
    }

    @Override
    public String getToolName(int toolFlag) {
        return null;
    }

    @Override
    public void addScanIssue(IScanIssue issue) {
        scanIssues.add(issue);
    }

    @Override
    public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
        return null;
    }

    @Override
    public String[][] getParameters(byte[] request) {
        return new String[0][];
    }

    @Override
    public String[] getHeaders(byte[] message) {
        return new String[0];
    }

    @Override
    public void registerMenuItem(String menuItemCaption, IMenuItemHandler menuItemHandler) {

    }
}
