package com.contrast;

import burp.IHttpService;

public class HttpService implements IHttpService {

    private String host;
    private int port;
    private String protocol;


    public HttpService(String host, int port, String protocol) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }
}
