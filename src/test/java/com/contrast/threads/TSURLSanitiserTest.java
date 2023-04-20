package com.contrast.threads;

import com.contrast.Logger;
import org.junit.Test;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;

import static org.junit.Assert.*;

public class TSURLSanitiserTest {

    @Test
    public void testWithGoodURL() throws MalformedURLException {
        String url = "https://example.contrastsecurity.com/Contrast";
        assertEquals(url,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }


    @Test
    public void testWithNoProtocol() throws MalformedURLException {
        String url = "example.contrastsecurity.com/Contrast";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithHTTPProtocol() throws MalformedURLException {
        String url = "http://example.contrastsecurity.com/Contrast";
        String expectedURL = "http://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNoRootContextProtocol() throws MalformedURLException {
        String url = "https://example.contrastsecurity.com/";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNoRootContextProtocolAndNoTrailingSlash() throws MalformedURLException {
        String url = "https://example.contrastsecurity.com";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNoProtocolNoRootContextProtocolAndNoTrailingSlash() throws MalformedURLException {
        String url = "example.contrastsecurity.com";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNoProtocolRootContextProtocolAndTrailingSlash() throws MalformedURLException {
        String url = "example.contrastsecurity.com/Contrast/";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithProtocolRootContextProtocolAndTrailingSlash() throws MalformedURLException {
        String url = "https://example.contrastsecurity.com/Contrast/";
        String expectedURL = "https://example.contrastsecurity.com/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNonStandardPath() throws MalformedURLException {
        String url = "https://example.flibber.com/bla/Contrast";
        String expectedURL = "https://example.flibber.com/bla/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    @Test
    public void testWithNonStandardPathWithTrailingSlash() throws MalformedURLException {
        String url = "https://example.flibber.com/bla/Contrast/";
        String expectedURL = "https://example.flibber.com/bla/Contrast";
        assertEquals(expectedURL,TSURLSanitiser.getSanitisedURL(url,getLogger()));
    }

    private Logger getLogger() {
        return new Logger(new PrintWriter(OutputStream.nullOutputStream()),new PrintWriter(OutputStream.nullOutputStream()));
    }

}