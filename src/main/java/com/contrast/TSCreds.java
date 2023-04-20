package com.contrast;

import burp.Components;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class TSCreds {


    private String url;
    private String apiKey;
    private String serviceKey;
    private String userName;
    private String org;

    public TSCreds(){}

    public TSCreds(String url, String apiKey, String serviceKey, String userName, String org) {
        this.url = url;
        this.apiKey = apiKey;
        this.serviceKey = serviceKey;
        this.userName = userName;
        this.org = org;
    }

    public TSCreds(String url, String apiKey, String serviceKey, String userName) {
        this.url = url;
        this.apiKey = apiKey;
        this.serviceKey = serviceKey;
        this.userName = userName;
        this.org = "";
    }

    public String getUrl() {
        return url;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getServiceKey() {
        return serviceKey;
    }

    public String getUserName() {
        return userName;
    }

    public String getOrg() {
        return org;
    }



    public static TSCreds getSelectedCreds(List<TSCreds> credsList) {
        Optional<String> orgID = getOrgID();
        if(orgID.isPresent()) {
            return credsList.stream().filter(tsc-> orgID.get().equals(tsc.getOrg())).findFirst().orElse(credsList.get(0));
        } else {
            return credsList.get(0);
        }
    }


    private static Optional<String> getOrgID() {
        if(Components.getOrgsCombo()!=null&&Components.getOrgsCombo().getSelectedItem()!=null) {
            return Optional.of(Components.getOrgsCombo().getSelectedItem().toString());
        } else {
            return Optional.empty();
        }
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TSCreds creds = (TSCreds) o;
        return Objects.equals(url, creds.url) && Objects.equals(apiKey, creds.apiKey) && Objects.equals(serviceKey, creds.serviceKey) && Objects.equals(userName, creds.userName) && Objects.equals(org, creds.org);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, apiKey, serviceKey, userName, org);
    }
}
