package com.contrast.threads;

import burp.Components;
import burp.DataModel;
import burp.PathTracePair;
import burp.Status;
import burp.StatusUpdater;
import burp.VulnTableResult;
import com.contrast.Logger;
import com.contrast.TSReader;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrast.model.Routes;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrast.threads.StoppableThread;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.HttpRequestResponse;
import com.contrastsecurity.models.Story;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class UpdateRouteTableThread extends StoppableThread {


    private final TSReader reader;
    private final DataModel dataModel;
    private final String orgID;
    private final String appID;
    private final Logger logger;
    private boolean stop = false;

    public UpdateRouteTableThread(TSReader reader, DataModel dataModel, String orgID, String appID, Logger logger) {
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
            Optional<Routes> routes = reader.getRoutes(orgID, appID);
            if (routes.isPresent()&&!stop) {
                Map<Route, Future<Optional<RouteCoverage>>> routeFutureMap = new HashMap<>();
                for (Route route : routes.get().getRoutes()) {
                    if(stop) {
                        break;
                    }
                    String routeID = route.getRoute_hash();
                    routeFutureMap.put(route, reader.getCoverageForTrace(orgID, appID, routeID));

                }
                for(Route route : routeFutureMap.keySet()) {
                    if(stop) {
                        break;
                    }
                    Optional<RouteCoverage> result = routeFutureMap.get(route).get();
                    dataModel.getRouteCoverageMap().put(route,result);
                    if(result.isPresent() ) {
                        int i =0;
                        for(RouteCoverageObservationResource observationResource : result.get().getObservations() ) {
                            if(stop) {
                                break;
                            }
                            dataModel.getRouteTableModel().addRow(new Object[]{true,observationResource.getUrl(),observationResource.getVerb(),false,getLastExercisedDate(route)});
                            i++;
                            if(i%5==0) {
                                Components.getRouteTable().updateUI();
                            }
                        }
                        Components.getRouteTable().updateUI();
                    }
                }
            }
            List<Future<TraceIDDecoractedHttpRequestResponse>> futureReqResponses = new ArrayList<>();
            for (Trace trace : dataModel.getTraces()) {
                if(stop) {
                    break;
                }
                futureReqResponses.add(reader.getHttpRequest(orgID,trace.getUuid()));
            }
            int futureCount = 0;
            for(Future<TraceIDDecoractedHttpRequestResponse> futureReqRes : futureReqResponses) {
                if(stop) {
                    break;
                }
                HttpRequestResponse hreqRes = futureReqRes.get().getRequestResponse();
                dataModel.getVulnRequests().add(futureReqRes.get());
                Optional<VulnTableResult> vulnTableResult = getVulnTableResult(hreqRes);
                if(vulnTableResult.isPresent()) {
                    dataModel.getRouteTableModel().addRow(new Object[]{true,vulnTableResult.get().getUrl(), vulnTableResult.get().getVerb(), true,""});
                    futureCount++;
                    if(futureCount%5==0) {
                        Components.getRouteTable().updateUI();
                    }
                }
            }
            Components.getRouteTable().updateUI();
            int traceCount = 0;
            for(PathTracePair pathTracePair : getPathsFromNonRequestVulns(orgID,reader)) {
                if(stop) {
                    break;
                }
                String path = pathTracePair.getPath();
                boolean isFound = false;
                for( int i = 0; i < dataModel.getRouteTableModel().getRowCount(); i++) {
                    if(stop) {
                        break;
                    }
                    String tablePath = dataModel.getRouteTableModel().getValueAt(i,1).toString();
                    if(tablePath.equals(path)) {
                        isFound = true;
                        break;
                    }
                }
                if(!isFound) {
                    dataModel.getRouteTableModel().addRow(new Object[]{true,path, "", true,""});
                    traceCount++;
                    if(traceCount%5==0) {
                        Components.getRouteTable().updateUI();
                    }
                }
                addNonRequestVulnToMap(path,pathTracePair.getTrace());
            }
            Components.getRouteTable().updateUI();
        } catch (IOException | InterruptedException | ExecutionException e) {
            StatusUpdater.updateStatus(Status.ERROR,dataModel);
            throw new RuntimeException(e);
        }
        updateRouteCoverageStats();
        StatusUpdater.updateStatus(Status.READY,dataModel);
    }

    private void updateRouteCoverageStats() {
        int routeCount = dataModel.getRouteCoverageMap().keySet().size();
        int exercisedCount = 0;
        for(Route route : dataModel.getRouteCoverageMap().keySet()) {
           if(!(route.getExercised()==null||route.getExercised()==0)) {
               exercisedCount++;
           }
        }
        if(exercisedCount!=0) {
            Components.getRouteStatsLabel().setText("Routes: " + routeCount + " | Exercised: " + exercisedCount + " | Percentage Exercised : " + ((exercisedCount * 100) / routeCount)+"%");
        } else {
            Components.getRouteStatsLabel().setText("Routes: " + routeCount + " | Exercised: " + exercisedCount + " | Percentage Exercised : 0%" );
        }
        Components.getRouteStatsLabel().updateUI();
    }

    private void addNonRequestVulnToMap(String path,Trace trace) {
        if(dataModel.getNonRequestPathVulnMap().containsKey(path)) {
            dataModel.getNonRequestPathVulnMap().get(path).add(trace);
        } else {
            Set<Trace> traceSet = new HashSet<>();
            traceSet.add(trace);
            dataModel.getNonRequestPathVulnMap().put(path,traceSet);
        }
    }


    private String getLastExercisedDate(Route route) {
        Long lastExercised = route.getExercised();
        if(lastExercised==null) {
            return "";
        } else {
            String dateString =  new Date(lastExercised).toString();
            dataModel.getFormattedDateMap().put(dateString,lastExercised);
            return dateString;
        }
    }

    private Optional<VulnTableResult> getVulnTableResult(HttpRequestResponse hreqRes) {
        if(hreqRes.getHttpRequest()!=null) {
            String text = hreqRes.getHttpRequest().getText();
            if(text.contains(" ")&&text.contains(" HTTP")) {
                String verb = text.split(" ")[0];
                String url = text.substring(text.indexOf(" ")).split(" HTTP")[0];
                return Optional.of(new VulnTableResult(url,verb));
            }
        }
        return Optional.empty();
    }

    private List<PathTracePair> getPathsFromNonRequestVulns(String orgID,TSReader reader) throws IOException {
        List<PathTracePair> paths = new ArrayList<>();
        for (Trace trace : dataModel.getTraces()) {
            StoryResponse response = getStoryResponse(orgID, trace.getUuid(), reader);
            Story story = response.getStory();
            if (story.getChapters() != null) {
                Optional<Chapter> chapter = story.getChapters().stream().filter(chp -> "properties".equals(chp.getType())).findFirst();
                if (chapter.isPresent() && chapter.get().getPropertyResources() != null && !chapter.get().getPropertyResources().isEmpty()) {
                    paths.add(new PathTracePair(chapter.get().getPropertyResources().get(0).getName(), trace));
                }
            }
        }
        return paths;
    }

    private StoryResponse getStoryResponse(String orgID, String traceID,TSReader reader) throws IOException {
        if(!dataModel.getTraceIDStoryMap().containsKey(traceID)) {
            reader.getStory(orgID,traceID).ifPresent(response -> dataModel.getTraceIDStoryMap().put(traceID,response));
        }
        return dataModel.getTraceIDStoryMap().get(traceID);
    }



    @Override
    public void notifyThread() {
        this.stop = true;
    }
}
