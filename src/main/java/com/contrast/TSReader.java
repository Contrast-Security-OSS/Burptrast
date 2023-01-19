package com.contrast;

import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrastsecurity.http.ServerFilterForm;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.Organization;
import com.contrastsecurity.models.RouteCoverageBySessionIDAndMetadataRequest;
import com.contrastsecurity.models.Server;
import com.contrastsecurity.models.Trace;
import com.contrastsecurity.models.TraceFilterBody;
import com.contrastsecurity.sdk.ContrastSDK;
import com.contrastsecurity.sdk.internal.GsonFactory;
import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public class TSReader {

    private final TSCreds creds;
    private ContrastSDK contrastSDK = null;

    private Gson gson = GsonFactory.create();
    public TSReader(TSCreds creds ) {
        this.creds = creds;
    }

    public List<Organization> getOrgs() throws IOException {
        return getSDK().getProfileOrganizations().getOrganizations();
    }

    public List<Server> getServers(String orgID) throws IOException {
        return getSDK().getServers(orgID, new ServerFilterForm()).getServers();
    }

    public Optional<Server> getServerForName(String orgID, String appName) throws IOException {
        List<Server> servers = getServers(orgID);
        return servers.stream().filter(server -> appName.equals(server.getName())).findFirst();
    }

    public List<Trace> getTraces(String orgID, String appId) throws IOException {
        TraceFilterBody body = new TraceFilterBody();
        RouteCoverageBySessionIDAndMetadataRequest request = new RouteCoverageBySessionIDAndMetadataRequest();
        return getSDK().getTraces(orgID,appId,body).getTraces();
    }

    public Optional<Routes> getRoutes(String orgID, String appID) throws IOException {
        String url = creds.getUrl()+"/api/ng/%s/applications/%s/route";
        url = String.format(url, orgID,appID);

        HttpURLConnection connection = getSDK().makeConnection(url,"GET");
        try {
            connection.connect();
            if (connection.getResponseCode() == 200) {
                try (InputStream is = connection.getInputStream()) {
                    String body = IOUtils.toString(is, StandardCharsets.UTF_8);

                    return Optional.of(gson.fromJson(body, Routes.class));
                }
            }
        } finally {
            connection.disconnect();
        }
        return Optional.empty();
    }

    public Optional<RouteCoverage> getCoverageForTrace(String orgID, String appID, String routeID) throws IOException {
        String url = creds.getUrl()+"/api/ng/%s/applications/%s/route/%s/observations";
        url = String.format(url, orgID,appID,routeID);
       HttpURLConnection connection = getSDK().makeConnection(url,"GET");
       try {
           connection.connect();
           if (connection.getResponseCode() == 200) {
               try (InputStream is = connection.getInputStream()) {
                   String body = IOUtils.toString(is, StandardCharsets.UTF_8);
                   return Optional.of(gson.fromJson(body,RouteCoverage.class));
               }
           }
       } finally {
           connection.disconnect();
       }
       return Optional.empty();
    }



    public List<Application> getApplications(String orgID) throws IOException {
        return getSDK().getApplications(orgID).getApplications();
    }



    public ContrastSDK getSDK() {
        if(contrastSDK==null) {
            contrastSDK = new ContrastSDK.Builder(creds.getUserName(), creds.getServiceKey(), creds.getApiKey())
                    .withApiUrl(creds.getUrl()+"/api")
                    .build();
            return contrastSDK;
        } else {
            return contrastSDK;
        }
    }




}
