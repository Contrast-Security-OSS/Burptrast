package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.IBurpExtenderCallbacks;
import burp.PortResolver;
import burp.SiteMapImporter;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.Logger;
import com.contrast.TSReader;

public class ImportRoutesToSiteMapThread extends StoppableThread {

    private final TSReader reader;
    private final DataModel dataModel;
    private final Logger logger;
    private final IBurpExtenderCallbacks callbacks;
    private boolean stop = false;

    public ImportRoutesToSiteMapThread(TSReader reader, DataModel dataModel, Logger logger, IBurpExtenderCallbacks callbacks) {
        this.reader = reader;
        this.dataModel = dataModel;
        this.logger = logger;
        this.callbacks = callbacks;
    }

    @Override
    public void run() {
        StatusUpdater.updateStatus(Status.LOADING,dataModel);
        new SiteMapImporter(dataModel,callbacks,logger,reader).importSiteMapToBurp(
                Components.getOrgsCombo().getSelectedItem().toString(),
                Components.getAppCombo().getSelectedItem().toString(),
                Components.getHostNameField().getText(),
                PortResolver.getPort(),
                Components.getProtocolCombo().getSelectedItem().toString(),
                Components.getAppContextField().getText()
        );
        StatusUpdater.updateStatus(Status.READY,dataModel);
    }


    @Override
    public void notifyThread() {
        this.stop = true;
    }
}
