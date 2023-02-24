package com.contrast;

import burp.IHttpRequestResponse;
import com.contrast.model.RouteCoverageObservationResource;
import com.contrastsecurity.models.HttpRequestResponse;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Converts Contrast's Endpoint Objects into the IHttpRequestResponse objects used by Burp's Sitemap.
 *
 */
public class RequestResponseGenerator {


    public String getNormalisedPath(String appContext, String url) {
        if(appContext==null||appContext.isEmpty()) {
            return url;
        }
        StringBuilder normalisedURL = new StringBuilder();
        if(!appContext.startsWith("/")) {
            appContext = "/"+appContext;
        }
        if(appContext.endsWith("/")) {
            appContext = appContext.substring(0,appContext.length()-1);
        }
        if(!url.startsWith("/")) {
            url = "/"+url;
        }
        return normalisedURL.append(appContext).append(url).toString();
    }

    /**
     * Converts the RouteCoverage data, along with the manually configured HttpService into example
     * IHttpRequestResponse objects used by Burp.
     * @param resource
     * @param service
     * @return
     */
    public IHttpRequestResponse getReqResForRouteCoverage(RouteCoverageObservationResource resource, HttpService service, String appContext) {
        return getReqResForRouteCoverage(resource.getUrl(),resource.getVerb(),service,appContext);
    }

    public IHttpRequestResponse getReqResForRouteCoverage(String url, String verb, HttpService service, String appContext) {
        String path = getNormalisedPath(appContext,url);
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
        reqRes.setComment("Found via Route Coverage");
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
            reqRes.setComment("Found via Assess Vulnerability");
            return Optional.of(reqRes);
        } else {
            return Optional.empty();
        }

    }

    public URL getURLFromHttpReq(IHttpRequestResponse httpRequestResponse) throws MalformedURLException {
        StringBuilder req  = new StringBuilder();
        req.append(httpRequestResponse.getHttpService().getProtocol());
        req.append("://");
        req.append(httpRequestResponse.getHttpService().getHost());
        req.append(":");
        req.append(httpRequestResponse.getHttpService().getPort());
        String payload = new String(httpRequestResponse.getRequest());
        int startPoint = payload.indexOf(" ");
        int endPoint = payload.indexOf("\n");
        String subPayload = payload.substring(startPoint+1,endPoint);
        subPayload = subPayload.substring(0,subPayload.lastIndexOf(" HTTP"));
        req.append(subPayload);
        return new URL(req.toString());
    }

}
