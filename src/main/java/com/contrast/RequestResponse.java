package com.contrast;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class RequestResponse implements IHttpRequestResponse {
    private IHttpService service;
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;

    public RequestResponse(){}

    public RequestResponse(IHttpRequestResponse reqRos) {
        setComment(reqRos.getComment());
        setHighlight(reqRos.getHighlight());
        setHttpService(reqRos.getHttpService());
        setRequest(reqRos.getRequest());
        setResponse(reqRos.getResponse());
    }


    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] bytes) {
        this.request = bytes;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] bytes) {
        this.response = bytes;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String s) {
        this.comment = s;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String s) {
        this.highlight = s;
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService iHttpService) {
        this.service = iHttpService;
    }
}
