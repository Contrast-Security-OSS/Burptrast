package com.contrast;

import burp.DataModel;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import com.contrast.model.RouteCoverage;
import com.contrast.model.Routes;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.exceptions.ContrastException;
import com.contrastsecurity.http.HttpMethod;
import com.contrastsecurity.http.RequestConstants;
import com.contrastsecurity.http.UrlBuilder;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.Applications;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Organization;
import com.contrastsecurity.models.Organizations;
import com.contrastsecurity.models.PropertyResource;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;
import com.contrastsecurity.models.TraceFilterBody;
import com.contrastsecurity.models.Traces;
import com.contrastsecurity.sdk.internal.GsonFactory;
import com.contrastsecurity.utils.ContrastSDKUtils;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
    private final DataModel dataModel;
    private final IBurpExtenderCallbacks callbacks;

    private ExecutorService executor = Executors.newFixedThreadPool(6);

    private Gson gson = GsonFactory.create();

    private UrlBuilder urlBuilder;

    public TSReader(TSCreds creds, Logger logger, DataModel dataModel, IBurpExtenderCallbacks callbacks) {
        this.creds = creds;
        this.logger = logger;
        this.dataModel = dataModel;
        this.callbacks = callbacks;
        this.urlBuilder = UrlBuilder.getInstance();
    }

    /**
     * Returns a list of Orgs.
     * @return
     * @throws IOException
     */
    public List<Organization> getOrgs() throws IOException, ContrastException {
        logger.logMessage("get orgs");
        byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+urlBuilder.getProfileOrganizationsUrl(),getHost(),getPort(),"");
        List<Organization> orgs =  gson.fromJson(new String(data), Organizations.class).getOrganizations();
        logger.logMessage("found" + orgs.size() +" orgs");
        return orgs;
    }


    /**
     * Returns a list of Traces ( Vulnerabilities ) for the specified App.
     * @param orgID
     * @param appId
     * @return
     * @throws IOException
     */
    public List<Trace> getTraces(String orgID, String appId) throws IOException, ContrastException {
        logger.logMessage("get traces for orgid : " + orgID + " appid " + appId);
        TraceFilterBody body = new TraceFilterBody();
        byte[] data = getHTTPRequest(HttpMethod.POST, getPath()+urlBuilder.getTracesWithBodyUrl(orgID, appId),getHost(),getPort(),gson.toJson(body));
        List<Trace> traces =  gson.fromJson(new String(data),Traces.class).getTraces();
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
    public Optional<Routes> getRoutes(String orgID, String appID) throws IOException,ContrastException {
        logger.logMessage("get routes for orgid : " + orgID + " appid " + appID);
        String url = "/ng/%s/applications/%s/route";
        url = String.format(url, orgID,appID);
        byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+url,getHost(),getPort(),"");
        if(data.length==0) {
            return Optional.empty();
        }
        Routes routes = gson.fromJson(new String(data), Routes.class);
        logger.logMessage("found "+routes.getRoutes().size() + " routes");
        return Optional.of(routes);
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
        String url = "/ng/%s/applications/%s/route/%s/observations";
        url = String.format(url, orgID,appID,routeID);
        String finalUrl = url;
        return executor.submit(() -> {
            Optional<RouteCoverage> result = Optional.empty();
            try {
                byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+finalUrl,getHost(),getPort(),"");
                if(data.length>0) {
                    result = Optional.of(gson.fromJson(new String(data), RouteCoverage.class));
                }
            } catch (IOException |ContrastException e) {
                logger.logException("unable to get coverage for trace",e);
                throw new RuntimeException(e);
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
    public Future<TraceIDDecoractedHttpRequestResponse> getHttpRequest(String orgID, String traceID) {
        return executor.submit(() -> {
            try {
                byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+ urlBuilder.getHttpRequestByTraceId(orgID, traceID),getHost(),getPort(),"");
                return new TraceIDDecoractedHttpRequestResponse(traceID,gson.fromJson(new String(data), HttpRequestResponse.class));
            } catch (IOException |ContrastException e) {
                logger.logException("unable to get HTTP Request for trace " ,e);
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
        byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+urlBuilder.getApplicationsUrl(orgID),getHost(),getPort(),"");
        List<Application> applications =  gson.fromJson(new String(data), Applications.class).getApplications();
        List<Application> sortedApps = new ArrayList<>(applications);
        sortedApps.sort(Comparator.comparingLong(Application::getLastSeen).reversed());
        logger.logMessage("found "+sortedApps.size() + " applications" );
        dataModel.setApplications(applications);
        return sortedApps;
    }

    public Optional<StoryResponse> getStory(String orgID, String traceID) throws IOException {
        byte[] data = getHTTPRequest(HttpMethod.GET, getPath()+urlBuilder.getStoryByTraceId(orgID, traceID),getHost(),getPort(),"");
        if(data.length>0) {
            String inputString = new String(data);
            StoryResponse story = gson.fromJson(inputString, StoryResponse.class);
            JsonObject object = (JsonObject) new JsonParser().parse(inputString);
            JsonObject storyObject = (JsonObject) object.get("story");
            if (storyObject != null) {
                JsonArray chaptersArray = (JsonArray) storyObject.get("chapters");
                List<Chapter> chapters = story.getStory().getChapters();
                if (chapters == null) {
                    chapters = new ArrayList<>();
                } else {
                    chapters.clear();
                }
                for (int i = 0; i < chaptersArray.size(); i++) {
                    JsonObject member = (JsonObject) chaptersArray.get(i);
                    Chapter chapter = gson.fromJson(member, Chapter.class);
                    chapters.add(chapter);
                    JsonObject properties = (JsonObject) member.get("properties");
                    if (properties != null) {
                        Set<Map.Entry<String, JsonElement>> entries = properties.entrySet();
                        Iterator<Map.Entry<String, JsonElement>> iter = entries.iterator();
                        List<PropertyResource> propertyResources = new ArrayList<>();
                        chapter.setPropertyResources(propertyResources);
                        while (iter.hasNext()) {
                            Map.Entry<String, JsonElement> prop = iter.next();
                            JsonElement entryValue = prop.getValue();
                            if (entryValue != null && entryValue.isJsonObject()) {
                                JsonObject obj = (JsonObject) entryValue;
                                JsonElement name = obj.get("name");
                                JsonElement value = obj.get("value");
                                if (name != null && value != null) {
                                    PropertyResource propertyResource = new PropertyResource();
                                    propertyResource.setName(name.getAsString());
                                    propertyResource.setValue(value.getAsString());
                                    propertyResources.add(propertyResource);
                                }
                            }
                        }
                    }
                }
            }
            return Optional.of(story);
        } else {
            return Optional.empty();
        }

    }




    private String getPath() throws MalformedURLException {
        String path =  new URL(creds.getUrl()).getPath();
        if(path.endsWith("/")) {
            path = path.substring(0,path.length()-1);
        }
        if(path.endsWith("/api")) {
            return path;
        } else {
            return path+"/api";
        }

    }

    private String getHost() throws MalformedURLException {
        return new URL(creds.getUrl()).getHost();
    }

    private int getPort() throws MalformedURLException {
        URL url =  new URL(creds.getUrl());
        int port = url.getPort();
        if(port==-1) {
            port =  url.getDefaultPort();
        }
        return port;
    }

    private byte[] getHTTPRequest(HttpMethod method, String path, String host, int port, String body) {
        IHttpService service = callbacks.getHelpers().buildHttpService(host,port,true);
        List<String> headers = new ArrayList<>();
        headers.add(method.name()+" "+ path+ " HTTP/2" );
        headers.add(RequestConstants.AUTHORIZATION+": "+  ContrastSDKUtils.makeAuthorizationToken(creds.getUserName(), creds.getServiceKey()));
        headers.add(RequestConstants.API_KEY+":"+creds.getApiKey());
        headers.add("Content-Type: application/json; charset=UTF-8");
        headers.add("User-Agent: Burptrast");
        headers.add("Host: "+host);
        byte[] message = callbacks.getHelpers().buildHttpMessage(headers,body.getBytes());
        IHttpRequestResponse requestResponse =  callbacks.makeHttpRequest(service,message,false);
        IResponseInfo info = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(info.getStatusCode()==200) {
            int bodyOffset = info.getBodyOffset();
            if (bodyOffset > 0) {
                return Arrays.copyOfRange(requestResponse.getResponse(), bodyOffset, requestResponse.getResponse().length);
            } else {
                return new byte[]{};
            }
        } else if(info.getStatusCode()==302||info.getStatusCode()==401) {
          throw new ContrastException("Unable to make request to TS API. HTTP Status Code: " + info.getStatusCode());
        } else {
            logger.logError("error retrieving data " +info.getStatusCode());
            int bodyOffset = info.getBodyOffset();
            if (bodyOffset > 0) {
                String bodyMessage =  new String(Arrays.copyOfRange(requestResponse.getResponse(), bodyOffset, requestResponse.getResponse().length));
                logger.logError(bodyMessage);
            }
            return new byte[]{};
        }
    }



}
