package com.contrast;

public class TSCreds {

    private String url;
    private String apiKey;
    private String serviceKey;

    private String userName;

    public TSCreds(String url, String apiKey, String serviceKey, String userName) {
        this.url = url;
        this.apiKey = apiKey;
        this.serviceKey = serviceKey;
        this.userName = userName;
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
}
