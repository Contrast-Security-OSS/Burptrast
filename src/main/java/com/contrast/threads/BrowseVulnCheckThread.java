package com.contrast.threads;

import burp.Components;
import burp.CorrelationIDAppender;
import burp.DataModel;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.PortResolver;
import burp.ScanIssue;
import com.contrast.HttpService;
import com.contrast.Logger;
import com.contrast.RequestResponseGenerator;
import com.contrast.TSCreds;
import com.contrast.TSReader;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

public class BrowseVulnCheckThread extends StoppableThread {

    private final TSReader reader;
    private final String orgID;
    private final String appID;
    private final CorrelationIDAppender idAppender;
    private final IBurpExtenderCallbacks callBacks;
    private final DataModel dataModel;
    private final Logger logger;

    private boolean shouldRun = true;

    private List<Trace> traces = new ArrayList<>();

    public BrowseVulnCheckThread(TSReader reader, String orgID, String appID, CorrelationIDAppender idAppender,
                                 IBurpExtenderCallbacks callbacks, DataModel dataModel, Logger logger) {
        this.reader = reader;
        this.orgID = orgID;
        this.appID = appID;
        this.idAppender = idAppender;
        this.callBacks = callbacks;
        this.dataModel = dataModel;
        this.logger = logger;
    }


    @Override
    public void run() {
        boolean firstRun = true;
        while(true) {
            if(!shouldRun) {
                break;
            }
            try {
                if(firstRun) {
                    traces.addAll(reader.getTraces(orgID,appID,Optional.of(dataModel)));
                    firstRun = false;
                } else {
                    dataModel.clearTraceTable();
                    List<Trace> newTraces = reader.getTraces(orgID,appID,Optional.of(dataModel));
                    List<String> oldTraceIDS = traces.stream().map(Trace::getUuid).collect(Collectors.toList());
                    List<Trace> unseenTraces = newTraces.stream().filter(trace -> !oldTraceIDS.contains(trace.getUuid())).collect(Collectors.toList());
                    for(Trace unseenTrace : unseenTraces) {
                        Future<TraceIDDecoractedHttpRequestResponse> request = reader.getHttpRequest(orgID,unseenTrace.getUuid());
                        TraceIDDecoractedHttpRequestResponse requestResponse = request.get();

                        if(requestResponse!=null&&requestResponse.getRequestResponse()!=null&&requestResponse.getRequestResponse().getHttpRequest()!=null&&requestResponse.getRequestResponse().getHttpRequest().getText()!=null) {
                            Optional<String> header = getCorrelationHeader(requestResponse.getRequestResponse().getHttpRequest().getText());
                            if(header.isPresent()) {
                                doPushVuln(requestResponse,unseenTrace);
                            }
                        }
                    }
                    traces = newTraces;
                }
                Thread.sleep(5000l);
            } catch (IOException | InterruptedException | ExecutionException e) {
                logger.logException("unable to process traces",e);
                throw new RuntimeException(e);
            }
        }
    }

    private Optional<String> getCorrelationHeader(String httpText) {
        Optional<String> result = Optional.empty();
        if(httpText!=null) {
            result = Arrays.stream(httpText.split("\n")).filter(this::isLineCorrelationHeader).findFirst();
        }
        return result;
    }

    private boolean isLineCorrelationHeader(String line) {
        if(line.contains(idAppender.getCorrelationID().toString())&&line.contains(CorrelationIDAppender.NAME)) {
            return true;
        } else {
            return false;
        }
    }


    private void doPushVuln(TraceIDDecoractedHttpRequestResponse requestResponse, Trace trace) throws IOException {
        RequestResponseGenerator generator = new RequestResponseGenerator();
        TSCreds creds = TSCreds.getSelectedCreds(dataModel.getTsCreds());

        HttpService service = getHttpService();

        Optional<IHttpRequestResponse> optional = generator.getReqResForTrace(requestResponse.getRequestResponse(), service);
        StoryResponse response = getStoryResponse(orgID, requestResponse.getTraceID(), reader);
        if (optional.isPresent()) {
            callBacks.addScanIssue(new ScanIssue(optional.get(), Optional.of(trace), logger, response, creds, orgID, appID));
            callBacks.addToSiteMap(optional.get());
        }
    }





    private StoryResponse getStoryResponse(String orgID, String traceID, TSReader reader) throws IOException {
        if (!dataModel.getTraceIDStoryMap().containsKey(traceID)) {
            reader.getStory(orgID, traceID).ifPresent(response ->  dataModel.getTraceIDStoryMap().put(traceID, response));
        }
        return dataModel.getTraceIDStoryMap().get(traceID);
    }

    private HttpService getHttpService() {
        return new HttpService( Components.getHostNameField().getText(),
                PortResolver.getPort(),Components.getProtocolCombo().getSelectedItem().toString());
    }



    @Override
    public void notifyThread() {
        shouldRun = false;
    }
}
