package com.contrast;

import burp.Components;
import burp.DataModel;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import burp.Status;
import burp.StatusUpdater;
import com.contrast.model.APIKey;
import com.contrast.model.RouteCoverage;
import com.contrast.model.Routes;
import com.contrast.model.ServiceKey;
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

import javax.swing.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
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

    private final List<TSCreds> creds;
    private final Logger logger;
    private final DataModel dataModel;
    private final IBurpExtenderCallbacks callbacks;
    private final Optional<String> tsURL;
    private final boolean errorInGUI;

    private ExecutorService executor = Executors.newFixedThreadPool(6);

    private Gson gson = GsonFactory.create();

    private UrlBuilder urlBuilder;

    public TSReader(List<TSCreds> creds, Logger logger, DataModel dataModel, IBurpExtenderCallbacks callbacks) {
        this.creds = creds;
        this.logger = logger;
        this.dataModel = dataModel;
        this.callbacks = callbacks;
        this.urlBuilder = UrlBuilder.getInstance();
        this.tsURL = Optional.empty();
        this.errorInGUI = false;
    }

    public TSReader(List<TSCreds> creds, Logger logger, DataModel dataModel, IBurpExtenderCallbacks callbacks,Optional<String> tsURL, boolean errorInGUI) {
        this.creds = creds;
        this.logger = logger;
        this.dataModel = dataModel;
        this.callbacks = callbacks;
        this.urlBuilder = UrlBuilder.getInstance();
        this.tsURL = tsURL;
        this.errorInGUI = errorInGUI;
    }

    public List<ICookie> login(String username,String password) throws IOException, ContrastException {
        logger.logMessage("login");
        String payloadPattern = "ui=false&username=%s&password=%s&sso=false";
        String payload = String.format(payloadPattern, URLEncoder.encode(username),URLEncoder.encode(password));
        IHttpRequestResponse requestResponse = getHTTPRequest(HttpMethod.POST, getPath().replace("/api","")+"/authenticate.html",
                getHost(),getPort(),payload,"Content-Type: application/x-www-form-urlencoded",false,Collections.emptyList(),Collections.emptyList());
        IResponseInfo info = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(validateResponse(info,requestResponse)) {
            return info.getCookies();
        } else {
            return Collections.emptyList();
        }
    }

    public Optional<ServiceKey> getServiceKey(List<ICookie> cookies, String xsrfValue)throws IOException, ContrastException {
        logger.logMessage("get service key");
        String xsrfHeader = "X-Xsrf-Token: "+xsrfValue;

        IHttpRequestResponse requestResponse = getHTTPRequest(HttpMethod.GET, getPath()+"/ng/profile/servicekey?expand=skip_links",getHost(),getPort(),"",
                "Content-Type: application/x-www-form-urlencoded",false,Collections.singletonList(xsrfHeader),cookies);
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(responseInfo.getStatusCode()==200) {
            ServiceKey key = gson.fromJson(
                    new String(getBodyData(callbacks.getHelpers().analyzeResponse(requestResponse.getResponse()), requestResponse)), ServiceKey.class);
            return Optional.of(key);
        } else {
            throw new ContrastException("Unable to retrieve Service key. Status code "+ responseInfo.getStatusCode());
        }
    }
    public List<Organization> getOrgs(List<ICookie> cookies, String xsrfValue) throws IOException, ContrastException {
        logger.logMessage("get orgs");
        String xsrfHeader = "X-Xsrf-Token: "+xsrfValue;
        IHttpRequestResponse requestResponse = getHTTPRequest(HttpMethod.GET, getPath()+urlBuilder.getProfileOrganizationsUrl(),getHost(),getPort(),"",
                "Content-Type: application/x-www-form-urlencoded",false,Collections.singletonList(xsrfHeader),cookies);
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(responseInfo.getStatusCode()==200) {
            List<Organization> orgs =  gson.fromJson(
                    new String(getBodyData(callbacks.getHelpers().analyzeResponse(requestResponse.getResponse()), requestResponse)),
                    Organizations.class).getOrganizations();
            logger.logMessage("found" + orgs.size() +" orgs");
            return orgs;
        } else {
            throw new ContrastException("Unable to retrieve Orgs. Status code "+ responseInfo.getStatusCode());
        }
    }

    public Optional<APIKey> getAPIKey(List<ICookie> cookies, String xsrfValue, String orgUuid) throws IOException, ContrastException {
        logger.logMessage("get service key");
        String xsrfHeader = "X-Xsrf-Token: "+xsrfValue;
        String path = getPath()+ String.format("/ng/%s/users/keys/apikey?expand=skip_links", orgUuid);
        IHttpRequestResponse requestResponse = getHTTPRequest(HttpMethod.GET, path,getHost(),getPort(),"",
                "Content-Type: application/x-www-form-urlencoded",false,Collections.singletonList(xsrfHeader),cookies);
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(responseInfo.getStatusCode()==200) {
            APIKey key = gson.fromJson(
                    new String(getBodyData(callbacks.getHelpers().analyzeResponse(requestResponse.getResponse()), requestResponse)), APIKey.class);
            return Optional.of(key);
        } else {
            throw new ContrastException("Unable to retrieve Service key. Status code "+ responseInfo.getStatusCode());
        }
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
    public List<Trace> getTraces(String orgID, String appId, Optional<DataModel> dataModel) throws IOException, ContrastException {
        List<Trace> tracesToReturn = new ArrayList<>();

        logger.logMessage("get traces for orgid : " + orgID + " appid " + appId);
        TraceFilterBody body = new TraceFilterBody();
        byte[] data = getHTTPRequest(HttpMethod.POST, getPath()+urlBuilder.getTracesWithBodyUrl(orgID, appId),getHost(),getPort(),gson.toJson(body));
        Traces traces = gson.fromJson(new String(data),Traces.class);
        List<Trace> traceLists = traces.getTraces();
        if(dataModel.isPresent()) {
            dataModel.get().getTraces().addAll(traces.getTraces());
            traces.getTraces().forEach(trace -> dataModel.get().getTraceTableModel().addRow(new Object[]{trace.getTitle(),trace.getRule(),trace.getSeverity()}));
            Components.getTraceTable().updateUI();
        }
        tracesToReturn.addAll(traceLists);
        if(traces.getTraces().size()<traces.getCount()) {
            tracesToReturn.addAll(getTracesPaginated(orgID,appId,traces.getTraces().size(),dataModel));
        }
        logger.logMessage("found " + tracesToReturn.size() + " traces");
        return tracesToReturn;
    }

    private List<Trace> getTracesPaginated(String orgID, String appId, int startPoint,Optional<DataModel> dataModel) throws MalformedURLException, UnsupportedEncodingException {
        List<Trace> tracesToReturn = new ArrayList<>();
        logger.logMessage("get traces for orgid : " + orgID + " appid " + appId);
        TraceFilterBody body = new TraceFilterBody();
        int requestLimit = 20;
        byte[] data = getHTTPRequest(HttpMethod.POST, getTraceURLPaginated(orgID,appId,startPoint,requestLimit),getHost(),getPort(),gson.toJson(body));
        Traces traces = gson.fromJson(new String(data),Traces.class);
        List<Trace> traceLists = traces.getTraces();
        tracesToReturn.addAll(traceLists);
        if(dataModel.isPresent()) {
            dataModel.get().getTraces().addAll(traces.getTraces());
            traces.getTraces().forEach(trace -> dataModel.get().getTraceTableModel().addRow(new Object[]{trace.getTitle(),trace.getRule(),trace.getSeverity()}));
            Components.getTraceTable().updateUI();
        }
        if(traces.getTraces().size()+startPoint<traces.getCount()) {
            tracesToReturn.addAll(getTracesPaginated(orgID,appId,traces.getTraces().size()+startPoint,dataModel));
        }
        logger.logMessage("found " + traceLists.size() + " traces");
        return tracesToReturn;
    }

    private String getTraceURLPaginated(String orgID,String appId, int startPoint, int sizeLimit) throws MalformedURLException, UnsupportedEncodingException {
        StringBuilder url = new StringBuilder();
        url.append(getPath()+urlBuilder.getTracesWithBodyUrl(orgID, appId));
        url.append("?limit="+sizeLimit);
        url.append("&offset="+startPoint);
        return url.toString();


    }


    /**
     * Returns a list of Routes ( Endpoints ) for the specified App.
     * @param orgID
     * @param appID
     * @return
     * @throws IOException
     */
    public Optional<Routes> getRoutes(String orgID, String appID) throws IOException,ContrastException {
       // getObservabilityData(orgID,appID);
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

    public void getObservabilityData(String orgId, String appID) {
        String url = "/api/ui/observe/v1/organizations/"+orgId+"/applications/"+appID+"/resources?page=0&size=100";
        try {
            byte[] data = getHTTPRequest(HttpMethod.POST, url, getHost(), getPort(), "");
            logger.logMessage(new String(data));
        } catch (IOException e) {
            logger.logException("unable to get observability data",e);
        }
    }




    private String getPath() throws MalformedURLException {
        String path =  new URL(getURL()).getPath();
        if(path.endsWith("/")) {
            path = path.substring(0,path.length()-1);
        }
        if(path.endsWith("/api")) {
            return path;
        } else {
            return path+"/api";
        }
    }

    private String getURL() {
        if(creds.isEmpty()&&tsURL.isPresent()) {
            return tsURL.get();
        } else if(creds.isEmpty()) {
            throw new ContrastException("No URL Present");
        } else {
            return creds.get(0).getUrl();
        }
    }

    private String getHost() throws MalformedURLException {
        return new URL(getURL()).getHost();
    }

    private boolean isHttps() throws MalformedURLException {
        return getURL().toLowerCase().trim().startsWith("https");
    }

    private int getPort() throws MalformedURLException {
        URL url =  new URL(getURL());
        int port = url.getPort();
        if(port==-1) {
            port =  url.getDefaultPort();
        }
        return port;
    }

    private byte[] getHTTPRequest(HttpMethod method, String path, String host, int port, String body) throws MalformedURLException {
        IHttpRequestResponse requestResponse =  getHTTPRequest(method,path,host,port,body,"Content-Type: application/json; charset=UTF-8",true,
                Collections.emptyList(),Collections.emptyList());
        IResponseInfo info = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
        if(validateResponse(info,requestResponse)) {
            return getBodyData(info,requestResponse);
        } else {
            return new byte[]{};
        }
    }





    private IHttpRequestResponse getHTTPRequest(HttpMethod method, String path, String host, int port, String body,
                                                String contentType, boolean useAPIAuth,List<String> additionalHeaders,List<ICookie> cookies) throws MalformedURLException {

        IHttpService service = callbacks.getHelpers().buildHttpService(host,port,isHttps());
        List<String> headers = new ArrayList<>();
        headers.add(method.name()+" "+ path+ " HTTP/1.1" );
        if(useAPIAuth) {
            TSCreds cred = TSCreds.getSelectedCreds(creds);
            headers.add(RequestConstants.AUTHORIZATION + ": " + ContrastSDKUtils.makeAuthorizationToken(cred.getUserName(), cred.getServiceKey()));
            headers.add(RequestConstants.API_KEY + ":" + cred.getApiKey());
        }
        headers.addAll(additionalHeaders);
        if(!cookies.isEmpty()) {
            headers.add(getFormattedCookieHeader(cookies));
        }
        headers.add(contentType);
        headers.add("User-Agent: Burptrast");
        headers.add("Host: "+host);
        byte[] message = callbacks.getHelpers().buildHttpMessage(headers,body.getBytes());
        IHttpRequestResponse requestResponse =  callbacks.makeHttpRequest(service,message,false);
        return requestResponse;
    }

    private String getFormattedCookieHeader(List<ICookie> cookies) {
        StringBuilder builder = new StringBuilder();
        builder.append("Cookie: ");
        for(ICookie cookie : cookies) {
            builder.append(cookie.getName());
            builder.append("=");
            builder.append(cookie.getValue());
            builder.append("; ");
        }

        return builder.toString().substring(0,builder.toString().length()-2);
    }

    private byte[] getBodyData(IResponseInfo info,IHttpRequestResponse requestResponse) {
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset > 0) {
            return Arrays.copyOfRange(requestResponse.getResponse(), bodyOffset, requestResponse.getResponse().length);
        } else {
            return new byte[]{};
        }
    }






    private boolean validateResponse(IResponseInfo info,IHttpRequestResponse requestResponse) {
        if(info.getStatusCode()==200) {
            return true;
        } else if(info.getStatusCode()==302||info.getStatusCode()==401) {
            if(errorInGUI) {
                StatusUpdater.updateStatus(Status.ERROR,dataModel);
                JOptionPane.showMessageDialog(null, "Unable to authenticate with TeamServer, status code : " + info.getStatusCode());
            }
            logger.logError("Unable to make request to TS API. HTTP Status Code: " + info.getStatusCode()+ " for request : "+new String(requestResponse.getRequest()));
            throw new ContrastException("Unable to make request to TS API. HTTP Status Code: " + info.getStatusCode()+ " for request : "+new String(requestResponse.getRequest()));
        } else {
            logger.logError("error retrieving data " +info.getStatusCode());
            int bodyOffset = info.getBodyOffset();
            if (bodyOffset > 0) {
                String bodyMessage =  new String(Arrays.copyOfRange(requestResponse.getResponse(), bodyOffset, requestResponse.getResponse().length));
                logger.logError(bodyMessage);
            }
            return false;
        }
    }



}
