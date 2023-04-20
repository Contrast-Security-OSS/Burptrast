package com.contrast.threads;

import com.contrast.Logger;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

public class TSURLSanitiser {


    public static String getSanitisedURL(String tsURL, Logger logger) throws MalformedURLException {
        logger.logMessage("Original TS URL : " +tsURL);
        String lowerCase = tsURL.toLowerCase(Locale.ROOT);
        if(!(lowerCase.startsWith("https://")||lowerCase.startsWith("http://"))) {
            tsURL = "https://"+tsURL;
        }
        URL url = new URL(tsURL);
        if(url.getPath()==null||url.getPath().equals("")||url.getPath().equals("/")) {
            if(tsURL.endsWith("/")) {
                tsURL = tsURL+"Contrast";
            } else {
                tsURL = tsURL+"/Contrast";
            }
        }
        if(url.getPath().endsWith("/Contrast/")) {
            tsURL = tsURL.substring(0,tsURL.length()-1);
        }
        logger.logMessage("Sanitised TS URL : " +tsURL);
        return tsURL;
    }
}
