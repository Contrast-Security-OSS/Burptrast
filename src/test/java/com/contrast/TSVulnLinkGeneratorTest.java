package com.contrast;

import org.junit.Test;

import static org.junit.Assert.*;

public class TSVulnLinkGeneratorTest {

    @Test
    public void testLinkGenerator() {
        String result = new TSVulnLinkGenerator().getURL("https://example.contrastsecurity.com/Contrast","123-456-789","987-654-321","abc-def-ghi");
        assertEquals("https://example.contrastsecurity.com/Contrast/static/ng/index.html#/123-456-789/applications/987-654-321/vulns/abc-def-ghi",result);
    }

}