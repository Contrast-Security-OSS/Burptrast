package com.contrast.model;

import java.util.List;

public class RouteCoverage {




    private List<RouteCoverageObservationResource> observations;

    public RouteCoverage(){}
    public RouteCoverage(List<RouteCoverageObservationResource> observations) {
        this.observations = observations;
    }

    public List<RouteCoverageObservationResource> getObservations() {
        return observations;
    }

    public void setObservations(List<RouteCoverageObservationResource> observations) {
        this.observations = observations;
    }
}
