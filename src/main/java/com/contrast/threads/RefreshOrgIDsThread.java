package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.Logger;
import com.contrast.TSReader;
import com.contrastsecurity.models.Organization;

import javax.swing.*;
import java.util.List;
import java.util.stream.Collectors;

public class RefreshOrgIDsThread extends StoppableThread {

    private final TSReader reader;
    private final DataModel dataModel;
    private final Logger logger;

    public RefreshOrgIDsThread(TSReader reader, DataModel dataModel, Logger logger) {
        this.reader = reader;
        this.dataModel = dataModel;
        this.logger = logger;
    }

    @Override
    public void run() {
        try {
            StatusUpdater.updateStatus(Status.LOADING,dataModel);
            List<String> orgIds = reader.getOrgs().stream().map(Organization::getOrgUuid).collect(Collectors.toList());
            orgIds.forEach(item-> Components.getOrgsCombo().addItem(item));
            RefreshAppIDsThread appIDsThread = new RefreshAppIDsThread(reader,dataModel,logger);
            dataModel.getThreadManager().addToThreadList(appIDsThread);
            dataModel.getThreadManager().getExecutor().execute(appIDsThread);
            StatusUpdater.updateStatus(Status.READY,dataModel);
        } catch (Exception e) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            JOptionPane.showMessageDialog(null, e+
                    "\n" +
                    "Most likely this is due to incorrect credentials in your credentials file." +
                    "\n" +
                    "See Error log under extensions -> Errors for further details.");
            logger.logException("Error occurred while refreshing org list",e);
            throw new RuntimeException(e);
        }
    }



    @Override
    public void notifyThread() {}
}
