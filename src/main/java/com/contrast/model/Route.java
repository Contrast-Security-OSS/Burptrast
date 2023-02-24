package com.contrast.model;

import java.util.Objects;

public class Route {

    private String signature;
    private int vulnerabilities;
    private String route_hash;

    private Long exercised;

    public Route() {
    }


    public Route(String signature, int vulnerabilities, String route_hash, Long exercised) {
        this.signature = signature;
        this.vulnerabilities = vulnerabilities;
        this.route_hash = route_hash;
        this.exercised = exercised;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public int getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(int vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public String getRoute_hash() {
        return route_hash;
    }

    public void setRoute_hash(String route_hash) {
        this.route_hash = route_hash;
    }

    public Long getExercised() {
        return exercised;
    }

    public void setExercised(Long exercised) {
        this.exercised = exercised;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Route route = (Route) o;
        return Objects.equals(route_hash, route.route_hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(route_hash);
    }
}
