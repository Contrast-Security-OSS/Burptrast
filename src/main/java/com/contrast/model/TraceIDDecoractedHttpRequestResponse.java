package com.contrast.model;

import com.contrastsecurity.models.HttpRequestResponse;

public class TraceIDDecoractedHttpRequestResponse {


    private final String traceID;
    private final HttpRequestResponse requestResponse;

    public TraceIDDecoractedHttpRequestResponse(String traceID, HttpRequestResponse requestResponse) {
        this.traceID = traceID;
        this.requestResponse = requestResponse;
    }

    public String getTraceID() {
        return traceID;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }
}
