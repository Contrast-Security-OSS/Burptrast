package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.Logger;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.model.APIKey;
import com.contrast.model.ServiceKey;
import com.contrastsecurity.models.Organization;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static burp.ContrastTab.enableButtons;
import static burp.ContrastTab.refreshOrgIDS;

public class CredentialsRetrieverThread extends StoppableThread{

    private final IBurpExtenderCallbacks callbacks;
    private final DataModel dataModel;
    private final Logger logger;
    private final String username;
    private final String password;
    private final String tsURL;

    public CredentialsRetrieverThread(IBurpExtenderCallbacks callbacks, DataModel dataModel, Logger logger, String username, String password, String tsURL) {
        this.callbacks = callbacks;
        this.dataModel = dataModel;
        this.logger = logger;
        this.username = username;
        this.password = password;
        this.tsURL = tsURL;
    }


    @Override
    public void run() {
        StatusUpdater.updateStatus(Status.LOADING,dataModel);
        boolean credsAdded = false;
        try {
            TSReader reader = new TSReader(dataModel.getTsCreds(),logger,dataModel,callbacks,Optional.of(getSanitisedTSURL()),true);

            List<ICookie> cookies = reader.login(username,password);
            if(!cookies.isEmpty()) {
                Optional<ICookie> xsrf = cookies.stream().filter(iCookie -> iCookie.getName().equals("XSRF-TOKEN")).filter(iCookie -> iCookie.getValue()!=null&&!iCookie.getValue().isEmpty()).findFirst();
                Optional<ICookie> ui_key = cookies.stream().filter(iCookie -> iCookie.getName().equals("contrast_ui_key")).filter(iCookie -> iCookie.getValue()!=null&&!iCookie.getValue().isEmpty()).findFirst();
                Optional<ICookie> session = cookies.stream().filter(iCookie -> iCookie.getName().equals("SESSION")).filter(iCookie -> iCookie.getValue()!=null&&!iCookie.getValue().isEmpty()).findFirst();
                if(validateCookie(xsrf)&&validateCookie(ui_key)&&validateCookie(session)) {
                    Optional<ServiceKey> serviceKey = reader.getServiceKey(Arrays.asList(xsrf.get(),ui_key.get(),session.get()), xsrf.get().getValue());
                    if(serviceKey.isPresent()) {
                        List<Organization> orgs = reader.getOrgs(Arrays.asList(xsrf.get(),ui_key.get(),session.get()), xsrf.get().getValue());
                        if(!orgs.isEmpty()) {
                            for(Organization org: orgs) {
                                Optional<APIKey> apiKey = reader.getAPIKey(Arrays.asList(xsrf.get(),ui_key.get(),session.get()), xsrf.get().getValue(), org.getOrgUuid());
                                if(apiKey.isPresent()) {
                                    TSCreds newCred = new TSCreds(getSanitisedTSURL(),apiKey.get().getApi_key(),serviceKey.get().getService_key(),serviceKey.get().getUser_uid(),org.getOrgUuid());
                                    dataModel.getTsCreds().add(newCred);
                                    credsAdded = true;
                                    Components.getSaveCredsFile().setEnabled(true);

                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            throw new RuntimeException(e);
        }
        if(!credsAdded) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            logger.logError("Unable to retrieve credentials");
            Components.getCredentialsStatusLabel().setText(Status.ERROR.getStatus());
            Components.getStatusLabel().setText(Status.ERROR.getStatus());

        } else {
            StatusUpdater.updateStatus(Status.READY,dataModel);
            enableButtons();
            refreshOrgIDS(callbacks);
            Components.getStatusLabel().setText(Status.READY.getStatus());
            Components.getCredentialsStatusLabel().setText(Status.READY.getStatus());
        }

    }

    private String getSanitisedTSURL() throws MalformedURLException {
       return TSURLSanitiser.getSanitisedURL(tsURL,logger);
    }

    private boolean validateCookie(Optional<ICookie> cookie) {
        if(cookie.isPresent()&&cookie.get().getValue()!=null&&!cookie.get().getValue().isEmpty()) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void notifyThread() {

    }
}
