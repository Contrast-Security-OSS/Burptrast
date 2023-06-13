package com.contrast;

import org.junit.Test;

import static org.junit.Assert.*;

public class RequestResponseGeneratorTest {


    @Test
    public void testNormalisedPathWithNoAppContext() {
        RequestResponseGenerator generator = new RequestResponseGenerator();
        String normalisedPath = generator.getNormalisedPath("","/location.html");
        assertEquals("/location.html",normalisedPath);
    }

    @Test
    public void testNormalisedPathWithNullAppContext() {
        RequestResponseGenerator generator = new RequestResponseGenerator();
        String normalisedPath = generator.getNormalisedPath(null,"/location.html");
        assertEquals("/location.html",normalisedPath);
    }

    @Test
    public void testNormalisedPathWithSingleSlashAppContext() {
        RequestResponseGenerator generator = new RequestResponseGenerator();
        String normalisedPath = generator.getNormalisedPath("/","/location.html");
        assertEquals("/location.html",normalisedPath);
    }

    @Test
    public void testNormalisedPathWithAppContext() {
        RequestResponseGenerator generator = new RequestResponseGenerator();
        String normalisedPath = generator.getNormalisedPath("/path","/location.html");
        assertEquals("/path/location.html",normalisedPath);
    }
}