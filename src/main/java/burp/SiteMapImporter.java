package burp;

import com.contrast.HttpService;
import com.contrast.Logger;
import com.contrast.RequestResponseGenerator;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.exceptions.ContrastException;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Story;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SiteMapImporter {

    private final DataModel dataModel;
    private final IBurpExtenderCallbacks callbacks;
    private final Logger logger;

    private final TSReader reader;

    public SiteMapImporter(DataModel dataModel, IBurpExtenderCallbacks callbacks, Logger logger, TSReader reader) {
        this.dataModel = dataModel;
        this.callbacks = callbacks;
        this.logger = logger;
        this.reader = reader;
    }

    public void importSiteMapToBurp(String orgID, String appName, String hostName, int port, String protocol, String appContext) {
        List<String> matchedPaths = new ArrayList<>();
        try {
            TSCreds creds = TSCreds.getSelectedCreds(dataModel.getTsCreds());
            String appID = dataModel.getAppNameIDMap().get(appName);
            RequestResponseGenerator generator = new RequestResponseGenerator();
            HttpService service = new HttpService(hostName, port, protocol);
            for (Route route : dataModel.getRouteCoverageMap().keySet()) {
                Optional<RouteCoverage> routeCoverage = dataModel.getRouteCoverageMap().get(route);
                if (routeCoverage.isPresent()) {
                    for (RouteCoverageObservationResource r : routeCoverage.get().getObservations()) {
                        if (isRouteSelected(r)) {
                            IHttpRequestResponse reqRes = generator.getReqResForRouteCoverage(r, service, appContext);
                            callbacks.addToSiteMap(reqRes);
                            List<Trace> traces = getTraceForPath(generator.getNormalisedPath(appContext, r.getUrl()), orgID, reader);
                            if (!traces.isEmpty()) {
                                matchedPaths.add(generator.getNormalisedPath(appContext, r.getUrl()));
                                for (Trace trace : traces) {
                                    if (dataModel.getTraceIDStoryMap().containsKey(trace.getUuid())) {
                                        ScanIssue scanIssue = new ScanIssue(reqRes, Optional.of(trace),
                                                logger, dataModel.getTraceIDStoryMap().get(trace.getUuid()), creds, orgID, appID);
                                        callbacks.addScanIssue(scanIssue);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (TraceIDDecoractedHttpRequestResponse hreqRes : dataModel.getVulnRequests()) {
                if (isTraceSelected(hreqRes.getRequestResponse())) {
                    Optional<IHttpRequestResponse> requestResponse = generator.getReqResForTrace(hreqRes.getRequestResponse(), service);
                    if (requestResponse.isPresent()) {
                        Optional<Trace> trace = dataModel.getTraces().stream().filter(t -> t.getUuid().equals(hreqRes.getTraceID())).findFirst();
                        StoryResponse response = getStoryResponse(orgID, hreqRes.getTraceID(), reader);
                        callbacks.addScanIssue(new ScanIssue(requestResponse.get(), trace, logger, response, creds, orgID, appID));
                        requestResponse.ifPresent(callbacks::addToSiteMap);
                    }
                }
            }
            for (String path : dataModel.getNonRequestPathVulnMap().keySet()) {
                if (!matchedPaths.contains(path)) {
                    IHttpRequestResponse reqRes = generator.getReqResForRouteCoverage(path, "", service, "");
                    reqRes.setComment("Found via Assess Vulnerability");
                    if(isNonRequestVulnSelected(path) ) {
                        for (Trace trace : dataModel.getNonRequestPathVulnMap().get(path)) {
                            ScanIssue scanIssue = new ScanIssue(reqRes, Optional.of(trace),
                                    logger, dataModel.getTraceIDStoryMap().get(trace.getUuid()),
                                    creds, orgID, appID);
                            callbacks.addScanIssue(scanIssue);
                        }
                    }
                }
            }


        } catch (IOException | ContrastException ex) {
            logger.logException("Error occurred importing site map", ex);
            throw new RuntimeException(ex);
        }

    }


    private boolean isRouteSelected(RouteCoverageObservationResource routeCoverage) {
        for (int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
            String path = (String) dataModel.getRouteTableModel().getValueAt(i, 1);
            String verb = (String) dataModel.getRouteTableModel().getValueAt(i, 2);
            if (routeCoverage.getVerb().equals(verb) && routeCoverage.getUrl().equals(path)) {
                return (boolean) dataModel.getRouteTableModel().getValueAt(i, 0);
            }
        }
        return false;
    }

    private StoryResponse getStoryResponse(String orgID, String traceID, TSReader reader) throws IOException {
        if (!dataModel.getTraceIDStoryMap().containsKey(traceID)) {
            reader.getStory(orgID, traceID)
                    .ifPresent(storyResponse -> dataModel.getTraceIDStoryMap().put(traceID, storyResponse)
                    );
        }
        return dataModel.getTraceIDStoryMap().get(traceID);
    }

    private List<Trace> getTraceForPath(String path, String orgID, TSReader reader) throws IOException {
        List<Trace> matchingTraces = new ArrayList<>();
        for (Trace trace : dataModel.getTraces()) {
            StoryResponse response = getStoryResponse(orgID, trace.getUuid(), reader);
            Story story = response.getStory();
            if (story.getChapters() != null) {
                Optional<Chapter> chapter = story.getChapters().stream().filter(chp -> "properties".equals(chp.getType())).findFirst();
                if (chapter.isPresent() && chapter.get().getPropertyResources() != null && !chapter.get().getPropertyResources().isEmpty()) {
                    String newPath = chapter.get().getPropertyResources().get(0).getName();
                    if (newPath.trim().equals(path.trim())) {
                        matchingTraces.add(trace);
                    }
                }
            }
        }
        return matchingTraces;
    }

    private Optional<VulnTableResult> getVulnTableResult(HttpRequestResponse hreqRes) {
        if (hreqRes.getHttpRequest() != null) {
            String text = hreqRes.getHttpRequest().getText();
            if (text.contains(" ") && text.contains(" HTTP")) {
                String verb = text.split(" ")[0];
                String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                return Optional.of(new VulnTableResult(url, verb));
            }
        }
        return Optional.empty();
    }

    private boolean isNonRequestVulnSelected(String nonVulnPath) {
        for (int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
            String path = (String) dataModel.getRouteTableModel().getValueAt(i, 1);
            if (nonVulnPath.trim().equals(path.trim())) {
                return (boolean) dataModel.getRouteTableModel().getValueAt(i, 0);
            }
        }
        return false;
    }

    private boolean isTraceSelected(HttpRequestResponse hreqRes) {
        Optional<VulnTableResult> vulnTableResult = getVulnTableResult(hreqRes);
        if (vulnTableResult.isPresent()) {
            for (int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
                String path = (String) dataModel.getRouteTableModel().getValueAt(i, 1);
                String verb = (String) dataModel.getRouteTableModel().getValueAt(i, 2);
                if (vulnTableResult.get().getUrl().trim().equals(path.trim()) && vulnTableResult.get().getVerb().equals(verb)) {
                    return (boolean) dataModel.getRouteTableModel().getValueAt(i, 0);
                }
            }
        }
        return false;
    }


}
