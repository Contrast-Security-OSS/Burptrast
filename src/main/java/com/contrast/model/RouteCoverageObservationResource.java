package com.contrast.model;

public class RouteCoverageObservationResource {

    private String url;
    private String verb;

    public RouteCoverageObservationResource(){}

    public RouteCoverageObservationResource(String url, String verb) {
        this.url = url;
        this.verb = verb;
    }

    public String getUrl() {
        return url;
    }

    public String getVerb() {
        return verb;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setVerb(String verb) {
        this.verb = verb;
    }
}
