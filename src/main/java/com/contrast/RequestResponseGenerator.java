package com.contrast;

import burp.IHttpRequestResponse;
import com.contrast.HttpService;
import com.contrast.RequestResponse;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrastsecurity.models.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class RequestResponseGenerator {


    public IHttpRequestResponse getReqRes(RouteCoverageObservationResource resource, HttpService service) {
        String path = resource.getUrl();
        String verb = resource.getVerb();
        if(verb==null||verb.isEmpty()) {
            verb = "GET";
        }
        StringBuilder message = new StringBuilder();
        message.append(verb);
        message.append(" ");
        message.append(path);
        message.append(" HTTP/1.1\r\n");
        RequestResponse reqRes = new RequestResponse();
        reqRes.setRequest(message.toString().getBytes(StandardCharsets.UTF_8));
        reqRes.setComment("");
        reqRes.setHttpService(service);
        return reqRes;
    }

    public Optional<IHttpRequestResponse> getReqRes(HttpRequestResponse hreqRes,HttpService service) {
        if(hreqRes.getHttpRequest()!=null) {
            RequestResponse reqRes = new RequestResponse();
            reqRes.setHttpService(service);
            reqRes.setRequest(hreqRes.getHttpRequest().getText().getBytes(StandardCharsets.UTF_8));
            return Optional.of(reqRes);
        } else {
            return Optional.empty();
        }

    }
}
