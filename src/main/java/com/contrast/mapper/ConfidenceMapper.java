package com.contrast.mapper;

import java.util.Arrays;
import java.util.List;

public enum ConfidenceMapper {

    CERTAIN(Arrays.asList("high"),"Certain"),
    FIRM(Arrays.asList("medium"),"Firm"),
    Tentative(Arrays.asList("low","none"),"Tentative");


    private final List<String> contrastConfidence;
    private final String burpConfidence;

    ConfidenceMapper(List<String> contrastConfidence, String burpConfidence) {

        this.contrastConfidence = contrastConfidence;
        this.burpConfidence = burpConfidence;
    }


    public List<String> getContrastConfidence() {
        return contrastConfidence;
    }

    public String getBurpConfidence() {
        return burpConfidence;
    }

    public static ConfidenceMapper getMappingForContrast(String contrastConfidence ) {
        for(ConfidenceMapper sev : ConfidenceMapper.values()) {
            if(sev.getContrastConfidence().contains(contrastConfidence.toLowerCase())) {
                return sev;
            }
        }
        throw new IllegalArgumentException("Unknown Contrast Confidence " + contrastConfidence);
    }


}
