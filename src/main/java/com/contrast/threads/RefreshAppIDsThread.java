package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.Logger;
import com.contrast.SortByAppNameComparator;
import com.contrast.SortByLastSeenComparator;
import com.contrast.SortType;
import com.contrast.TSReader;
import com.contrastsecurity.models.Application;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

public class RefreshAppIDsThread extends StoppableThread {

    private final TSReader reader;
    private final DataModel dataModel;
    private final Logger logger;

    public RefreshAppIDsThread(TSReader reader, DataModel dataModel,Logger logger) {
        this.reader = reader;
        this.dataModel = dataModel;
        this.logger = logger;
    }


    @Override
    public void run() {
        StatusUpdater.updateStatus(Status.LOADING,dataModel);
        try {
            List<Application> applications = reader.getApplications(Objects.requireNonNull(Components.getOrgsCombo().getSelectedItem()).toString());
            applications.forEach(application -> dataModel.getAppNameIDMap().put(application.getName(), application.getId()));
            if(dataModel.getSortType().equals(SortType.SORT_BY_NAME)) {
                applications.sort(new SortByAppNameComparator());
            } else {
                applications.sort(new SortByLastSeenComparator());
            }
            applications.forEach(application -> Components.getAppCombo().addItem(application.getName()));
        } catch (IOException e) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            logger.logException("Unable to retrieve applications",e);
            throw new RuntimeException(e);
        }
        StatusUpdater.updateStatus(Status.READY,dataModel);
    }



    @Override
    public void notifyThread() {

    }
}
