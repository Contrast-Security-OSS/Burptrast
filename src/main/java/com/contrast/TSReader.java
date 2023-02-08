package com.contrast;

import com.contrast.model.RouteCoverage;
import com.contrast.model.Routes;
import com.contrastsecurity.http.ServerFilterForm;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Organization;
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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * TSReader manages calls to TeamServer, which are made using the Contrast-SDK.
 * Some calls, those that need to be made multiple times per application are run within a threadpool to improve
 * performance.
 */
public class TSReader {

    private final TSCreds creds;
    private final Logger logger;
    private final ContrastSDK contrastSDK;

    private ExecutorService executor = Executors.newFixedThreadPool(6);

    private Gson gson = GsonFactory.create();


    public TSReader(TSCreds creds, Logger logger ) {
        this.creds = creds;
        this.logger = logger;
        contrastSDK = new ContrastSDK.Builder(creds.getUserName(), creds.getServiceKey(), creds.getApiKey())
                .withApiUrl(creds.getUrl()+"/api")
                .build();
    }

    /**
     * Returns a list of Orgs.
     * @return
     * @throws IOException
     */
    public List<Organization> getOrgs() throws IOException {
        logger.logMessage("get orgs");
        List<Organization> orgs =  getSDK().getProfileOrganizations().getOrganizations();
        logger.logMessage("found" + orgs.size() +" orgs");
        return orgs;
    }

    /**
     * Returns a list of Servers connected to the specified Org.
     * @param orgID
     * @return
     * @throws IOException
     */
    public List<Server> getServers(String orgID) throws IOException {
        return getSDK().getServers(orgID, new ServerFilterForm()).getServers();
    }

    /**
     * Returns an Optional Server for the specified Org and App Name.
     * @param orgID
     * @param appName
     * @return
     * @throws IOException
     */
    public Optional<Server> getServerForName(String orgID, String appName) throws IOException {
        List<Server> servers = getServers(orgID);
        return servers.stream().filter(server -> appName.equals(server.getName())).findFirst();
    }

    /**
     * Returns a list of Traces ( Vulnerabilities ) for the specified App.
     * @param orgID
     * @param appId
     * @return
     * @throws IOException
     */
    public List<Trace> getTraces(String orgID, String appId) throws IOException {
        logger.logMessage("get traces for orgid : " + orgID + " appid " + appId);

        TraceFilterBody body = new TraceFilterBody();
        List<Trace> traces =  getSDK().getTraces(orgID,appId,body).getTraces();
        logger.logMessage("found " + traces.size() + " traces");
        return traces;
    }

    /**
     * Returns a list of Routes ( Endpoints ) for the specified App.
     * @param orgID
     * @param appId
     * @return
     * @throws IOException
     */
    public Optional<Routes> getRoutes(String orgID, String appID) throws IOException {
        logger.logMessage("get routes for orgid : " + orgID + " appid " + appID);

        String url = creds.getUrl()+"/api/ng/%s/applications/%s/route";
        url = String.format(url, orgID,appID);

        HttpURLConnection connection = getSDK().makeConnection(url,"GET");
        Optional<Routes> result = Optional.empty();
        try {
            connection.connect();
            if (connection.getResponseCode() == 200) {
                try (InputStream is = connection.getInputStream()) {
                    String body = IOUtils.toString(is, StandardCharsets.UTF_8);

                    result =  Optional.of(gson.fromJson(body, Routes.class));
                }
            }
        } finally {
            connection.disconnect();
        }
        result.ifPresent(rtes-> logger.logMessage("found "+rtes.getRoutes().size() + " routes"));
        return result;
    }

    /**
     * Returns a Future, Optional Route Coverage for the specified Trace. This contains the HTTP Verb and path
     * that is used to populate the Route Table.
     * @param orgID
     * @param appID
     * @param routeID
     * @return
     */
    public Future<Optional<RouteCoverage>> getCoverageForTrace(String orgID, String appID, String routeID)  {
        logger.logMessage("get route observations for  for orgid : " + orgID + " appid " + appID + " routeid " + routeID);
        String url = creds.getUrl()+"/api/ng/%s/applications/%s/route/%s/observations";
        url = String.format(url, orgID,appID,routeID);
        String finalUrl = url;
        return executor.submit(() -> {
            HttpURLConnection connection = null;
            Optional<RouteCoverage> result = Optional.empty();
            try {
                connection = getSDK().makeConnection(finalUrl,"GET");
                connection.connect();
                if (connection.getResponseCode() == 200) {
                    try (InputStream is = connection.getInputStream()) {
                        String body = IOUtils.toString(is, StandardCharsets.UTF_8);
                        result =  Optional.of(gson.fromJson(body,RouteCoverage.class));
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                if(connection!=null) {
                    connection.disconnect();
                }
            }
            result.ifPresent(rteCoverage-> logger.logMessage("found "+rteCoverage.getObservations().size() + " route observations"));
            return result;
        });

    }


    /**
     * Returns the HTTP Request that triggered the vulnerability finding. This is used to populate the Route Table
     * @param orgID
     * @param traceID
     * @return
     */
    public Future<HttpRequestResponse> getHttpRequest(String orgID, String traceID) {
        return executor.submit(() -> {
            try {
                return getSDK().getHttpRequest(orgID,traceID);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }


    /**
     * Returns a list of applications, sorted by last seen.
     * @param orgID
     * @return
     * @throws IOException
     */
    public List<Application> getApplications(String orgID) throws IOException {
        logger.logMessage("get applications for orgid : " + orgID );

        List<Application> applications =  getSDK().getApplications(orgID).getApplications();
        List<Application> sortedApps = new ArrayList<>(applications);
        sortedApps.sort(Comparator.comparingLong(Application::getLastSeen).reversed());
        logger.logMessage("found "+sortedApps.size() + " applications" );
        return sortedApps;
    }



    public ContrastSDK getSDK() {
        return contrastSDK;
    }




}
