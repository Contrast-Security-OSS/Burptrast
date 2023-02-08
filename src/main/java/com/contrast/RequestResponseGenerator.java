package com.contrast;

import burp.IHttpRequestResponse;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrastsecurity.models.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Converts Contrast's Endpoint Objects into the IHttpRequestResponse objects used by Burp's Sitemap.
 *
 */
public class RequestResponseGenerator {


    /**
     * Converts the RouteCoverage data, along with the manually configured HttpService into example
     * IHttpRequestResponse objects used by Burp.
     * @param resource
     * @param service
     * @return
     */
    public IHttpRequestResponse getReqResForRouteCoverage(RouteCoverageObservationResource resource, HttpService service) {
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

    /**
     * Converts Contrast's HttpRequestResponse from trace data to Burps sitemap object
     * @param hreqRes
     * @param service
     * @return
     */
    public Optional<IHttpRequestResponse> getReqResForTrace(HttpRequestResponse hreqRes, HttpService service) {
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
