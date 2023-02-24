package com.contrast;

import org.junit.Test;

import static org.junit.Assert.*;

public class HTMLSanitiserTest {



    @Test
    public void testWithValidHTML() {
        String data = "some <b>data</b> <a href=\"http://example.com\">example link</a> <br />";
        HTMLSanitiser sanitiser = new HTMLSanitiser();
        assertEquals(data,sanitiser.sanitiseHTML(data));
    }


    @Test
    public void testWithXSSInjection() {
        String data = "some <b>data</b> <a href=\"http://example.com\">example link</a> <script>alert('hello')</script> <br />";
        HTMLSanitiser sanitiser = new HTMLSanitiser();
        assertEquals("some <b>data</b> <a href=\"http://example.com\">example link</a>  <br />",sanitiser.sanitiseHTML(data));
    }



}