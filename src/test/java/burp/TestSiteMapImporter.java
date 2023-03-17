package burp;

import com.contrast.Logger;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.mapper.ConfidenceMapper;
import com.contrast.mapper.IssueTypeMapper;
import com.contrast.mapper.SeverityMapper;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.HttpRequest;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Risk;
import com.contrastsecurity.models.Story;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.Test;

import javax.swing.table.DefaultTableModel;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestSiteMapImporter {


    @Test
    public void testWithOneVulnRouteSelected() {
        String orgID = "randomorgid";
        String appName = "test-app";
        String appID = "randomappid";
        String hostName = "localhost";
        int port = 8080;
        String protocol = "http";
        String appcontext = "/flibber";
        TestableCallBack callBack = new TestableCallBack();
        DataModel model = getDataModel(appName,appID);
        model.getTraces().addAll(getTraces());
        getStories().forEach(storyResponse -> model.getTraceIDStoryMap().put(storyResponse.getStory().getTraceId(),storyResponse));
        model.setRouteTableModel(getTable(Arrays.asList("/path1","/path2","/path3"),Arrays.asList("/path1"),Arrays.asList("GET","GET","GET")));
        model.getVulnRequests().addAll(getVulnRequests());
        SiteMapImporter siteMapImporter = new SiteMapImporter(model,callBack,getSystemOutLogger(),getTestTSReader(Optional.empty()));
        siteMapImporter.importSiteMapToBurp(orgID,appName,hostName,port,protocol,appcontext);
        assertEquals(1,callBack.getScanIssues().size());
        assertEquals(1,callBack.getRequestResponses().size());
        assertEquals("sql injection : Found by Assess", callBack.getScanIssues().get(0).getIssueName());
        assertEquals(IssueTypeMapper.SQL_INJECTION.getBurpType().intValue(), callBack.getScanIssues().get(0).getIssueType());
        assertEquals("risk text", callBack.getScanIssues().get(0).getIssueBackground());
        assertEquals("<a href=\"http://example.com/static/ng/index.html#/randomorgid/applications/randomappid/vulns/path1\">" +
                        "Vulnerability Details</a><br /><b>chapter type</b><br />message body<br />intro text<br />",
                callBack.getScanIssues().get(0).getIssueDetail());
        assertEquals(SeverityMapper.MEDIUM.getBurpSeverity(),callBack.getScanIssues().get(0).getSeverity());
        assertEquals(ConfidenceMapper.CERTAIN.getBurpConfidence(),callBack.getScanIssues().get(0).getConfidence());
    }

    @Test
    public void testWithAllVulnRouteSelected() {
        String orgID = "randomorgid";
        String appName = "test-app";
        String appID = "randomappid";
        String hostName = "localhost";
        int port = 8080;
        String protocol = "http";
        String appcontext = "/flibber";
        TestableCallBack callBack = new TestableCallBack();
        DataModel model = getDataModel(appName,appID);
        model.getTraces().addAll(getTraces());
        getStories().forEach(storyResponse -> model.getTraceIDStoryMap().put(storyResponse.getStory().getTraceId(),storyResponse));
        model.setRouteTableModel(getTable(Arrays.asList("/path1","/path2","/path3"),Arrays.asList("/path1","/path2","/path3"),Arrays.asList("GET","GET","GET")));
        model.getVulnRequests().addAll(getVulnRequests());
        SiteMapImporter siteMapImporter = new SiteMapImporter(model,callBack,getSystemOutLogger(),getTestTSReader(Optional.empty()));
        siteMapImporter.importSiteMapToBurp(orgID,appName,hostName,port,protocol,appcontext);

        assertEquals(3,callBack.getScanIssues().size());
        assertEquals(3,callBack.getRequestResponses().size());
    }

    @Test
    public void testWithARouteSelected() {
        String orgID = "randomorgid";
        String appName = "test-app";
        String appID = "randomappid";
        String hostName = "localhost";
        int port = 8080;
        String protocol = "http";
        String appcontext = "/flibber";
        TestableCallBack callBack = new TestableCallBack();
        DataModel model = getDataModel(appName,appID);
        model.getTraces().addAll(getTraces());
        getStories().forEach(storyResponse -> model.getTraceIDStoryMap().put(storyResponse.getStory().getTraceId(),storyResponse));
        model.setRouteTableModel(getTable(Arrays.asList("/route1","/route2","/route3"),Arrays.asList("/route1"),Arrays.asList("GET","GET","POST")));
        model.getVulnRequests().addAll(getVulnRequests());
        addRoutes(model);
        SiteMapImporter siteMapImporter = new SiteMapImporter(model,callBack,getSystemOutLogger(),getTestTSReader(Optional.empty()));
        siteMapImporter.importSiteMapToBurp(orgID,appName,hostName,port,protocol,appcontext);

        assertEquals(1,callBack.getRequestResponses().size());
        assertTrue(new String(callBack.getRequestResponses().get(0).getRequest()).startsWith("GET /flibber/route1"));
    }

    @Test
    public void testWithAllRouteSelected() {
        String orgID = "randomorgid";
        String appName = "test-app";
        String appID = "randomappid";
        String hostName = "localhost";
        int port = 8080;
        String protocol = "http";
        String appcontext = "/flibber";
        TestableCallBack callBack = new TestableCallBack();
        DataModel model = getDataModel(appName,appID);
        model.getTraces().addAll(getTraces());
        getStories().forEach(storyResponse -> model.getTraceIDStoryMap().put(storyResponse.getStory().getTraceId(),storyResponse));
        model.setRouteTableModel(getTable(Arrays.asList("/route1","/route2","/route3"),Arrays.asList("/route1","/route2","/route3"),Arrays.asList("GET","GET","POST")));
        model.getVulnRequests().addAll(getVulnRequests());
        addRoutes(model);
        SiteMapImporter siteMapImporter = new SiteMapImporter(model,callBack,getSystemOutLogger(),getTestTSReader(Optional.empty()));
        siteMapImporter.importSiteMapToBurp(orgID,appName,hostName,port,protocol,appcontext);

        assertEquals(3,callBack.getRequestResponses().size());
        assertTrue(new String(callBack.getRequestResponses().get(0).getRequest()).startsWith("GET /flibber/route1"));
        assertTrue(new String(callBack.getRequestResponses().get(1).getRequest()).startsWith("GET /flibber/route2"));
        assertTrue(new String(callBack.getRequestResponses().get(2).getRequest()).startsWith("POST /flibber/route3"));

    }

    private void addRoutes(DataModel dataModel) {
        Route route1 = new Route();
        route1.setRoute_hash("route1");
        RouteCoverage routeCoverage1 = new RouteCoverage();
        List<RouteCoverageObservationResource> observationResources1 = new ArrayList<>();
        routeCoverage1.setObservations(observationResources1);
        observationResources1.add(getObservationResource("/route1","GET"));
        observationResources1.add(getObservationResource("/route2","GET"));
        observationResources1.add(getObservationResource("/route3","POST"));
        dataModel.getRouteCoverageMap().put(route1,Optional.of(routeCoverage1));
    }

    private RouteCoverageObservationResource getObservationResource(String url, String verb) {
        RouteCoverageObservationResource observationResource = new RouteCoverageObservationResource();
        observationResource.setUrl(url);
        observationResource.setVerb(verb);
        return observationResource;

    }

    private List<StoryResponse> getStories() {
        return Arrays.asList(getStoryResponse("path1","risk text","chapter type","message body","intro text"),
                getStoryResponse("path2","risk text2","chapter type2","message body2","intro text2"),
                getStoryResponse("path3","risk text3","chapter type3","message body3","intro text3"));
    }

    private StoryResponse getStoryResponse(String id, String riskText, String chapterType, String chapterIntro,String chapterBody ) {
        StoryResponse response1 = new StoryResponse();
        Story story1 = new Story();
        response1.setStory(story1);
        story1.setTraceId(id);
        Risk risk1 = new Risk();
        risk1.setText(riskText);
        story1.setRisk(risk1);
        Chapter chapter1 = new Chapter();
        chapter1.setType(chapterType);
        chapter1.setBody(chapterBody);
        chapter1.setIntroText(chapterIntro);
        story1.setChapters(Arrays.asList(chapter1));
        return response1;
    }

    private List<Trace> getTraces() {
        return Arrays.asList(
                getTrace("path1","sql-injection","sql injection",
                    SeverityMapper.MEDIUM.getContrastSeverity().get(0),
                    ConfidenceMapper.CERTAIN.getContrastConfidence().get(0)),
                getTrace("path2", IssueTypeMapper.HEADER_INJECTION.getContrastType(),"Header Injection",
                        SeverityMapper.MEDIUM.getContrastSeverity().get(0),
                        ConfidenceMapper.CERTAIN.getContrastConfidence().get(0)),
                getTrace("path3", IssueTypeMapper.COMMAND_INJECTION.getContrastType(),"Command Injection",
                        SeverityMapper.MEDIUM.getContrastSeverity().get(0),
                        ConfidenceMapper.CERTAIN.getContrastConfidence().get(0))
                );
    }

    private Trace getTrace(String traceID, String issueType, String title,String severity,String likelihood) {
        Gson gson = new Gson();
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("uuid",traceID);
        jsonObject.addProperty("rule_name",issueType);
        jsonObject.addProperty("title",title);
        jsonObject.addProperty("severity",severity);
        jsonObject.addProperty("likelihood",likelihood);
        return gson.fromJson(jsonObject, Trace.class);
    }

    private List<TraceIDDecoractedHttpRequestResponse> getVulnRequests() {
        List<TraceIDDecoractedHttpRequestResponse> vulns = new ArrayList<>();
        vulns.add(new TraceIDDecoractedHttpRequestResponse("path1",getRequestResponse("/path1")));
        vulns.add(new TraceIDDecoractedHttpRequestResponse("path2",getRequestResponse("/path2")));
        vulns.add(new TraceIDDecoractedHttpRequestResponse("path3",getRequestResponse("/path3")));

        return vulns;
    }

    private DefaultTableModel getTable(List<String> paths, List<String> selectedPaths,List<String> verbs) {
        DefaultTableModel routeTable = new DefaultTableModel();
        routeTable.setColumnIdentifiers(ContrastTab.ROUTE_TABLE_COL_NAMES);
        for(int i =0;i<paths.size();i++) {
            String path = paths.get(i);
            String verb = verbs.get(i);
            routeTable.addRow(new Object[]{selectedPaths.contains(path),path,verb,true,null});
        }
        return routeTable;
    }


    private HttpRequestResponse getRequestResponse(String path) {
        StringBuilder message = new StringBuilder();
        message.append("GET ").append(path).append(" ").append("HTTP/1.1\n");
        HttpRequestResponse reqRes = new HttpRequestResponse();
        Gson gson = new Gson();
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("text",message.toString());
        reqRes.setHttpRequest(gson.fromJson(jsonObject, HttpRequest.class));
        return reqRes;
    }

    private TSReader getTestTSReader(final Optional<Routes> routes) {
        return new TSReader(getTestCreds(),null,null,null) {
            @Override
            public Optional<Routes> getRoutes(String orgID, String appID) {
                return routes;
            }
        };
    }

    private TSCreds getTestCreds() {
        return new TSCreds("http://example.com","example","example","example");
    }

    private DataModel getDataModel(String appName, String appID) {
        DataModel dataModel = new DataModel();
        dataModel.setCredentials(Optional.of(getTestCreds()));
        dataModel.getAppNameIDMap().put(appName,appID);
        return dataModel;
    }

    private Logger getSystemOutLogger() {
        return new Logger(new PrintWriter(System.out),new PrintWriter(System.err));
    }



}