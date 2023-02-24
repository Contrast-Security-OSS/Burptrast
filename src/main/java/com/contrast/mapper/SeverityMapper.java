package com.contrast.mapper;

import java.util.Arrays;
import java.util.List;

public enum SeverityMapper {


    HIGH(Arrays.asList("critical","high"),"High"),
    MEDIUM(Arrays.asList("medium"),"Medium"),
    LOW(Arrays.asList("low"),"Low"),
    INFORMATION(Arrays.asList("note"),"Information");




    private List<String> contrastSeverity;
    private String burpSeverity;


    SeverityMapper(List<String> contrastSeverity, String burpSeverity) {
        this.contrastSeverity = contrastSeverity;
        this.burpSeverity = burpSeverity;
    }


    public String getBurpSeverity() {
        return burpSeverity;
    }

    public List<String> getContrastSeverity() {
        return contrastSeverity;
    }

    public static SeverityMapper getMappingForContrast(String contrastSeverity ) {
        for(SeverityMapper sev : SeverityMapper.values()) {
            if(sev.getContrastSeverity().contains(contrastSeverity.toLowerCase())) {
                return sev;
            }
        }
        throw new IllegalArgumentException("Unknown Contrast Severity " + contrastSeverity);
    }

}
