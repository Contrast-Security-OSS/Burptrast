package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.Logger;
import com.contrast.TSReader;
import com.contrast.threads.StoppableThread;

import java.io.IOException;
import java.util.Optional;

public class UpdateTraceTableThread extends StoppableThread {


    private final TSReader reader;
    private final DataModel dataModel;
    private final String orgID;
    private final String appID;
    private final Logger logger;


    public UpdateTraceTableThread(TSReader reader, DataModel dataModel, String orgID, String appID, Logger logger) {
        this.reader = reader;
        this.dataModel = dataModel;
        this.orgID = orgID;
        this.appID = appID;
        this.logger = logger;
    }


    @Override
    public void run() {
        try {
            StatusUpdater.updateStatus(Status.LOADING,dataModel);
            dataModel.getTraces().clear();
            reader.getTraces(orgID,appID, Optional.of(dataModel));
            Components.getTraceTable().updateUI();
        } catch (IOException e) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            logger.logException("Error occurred while retrieving traces",e);
            throw new RuntimeException(e);
        }
        StatusUpdater.updateStatus(Status.READY,dataModel);

    }


    @Override
    public void notifyThread() {
    }



}
