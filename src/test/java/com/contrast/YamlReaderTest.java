package com.contrast;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

import static org.junit.Assert.*;

public class YamlReaderTest {


    @Test
    public void testWithValidYaml() throws IOException, URISyntaxException {
        File contrastFile = new File(YamlReaderTest.class.getResource("/contrast_security.yaml").toURI());
        YamlReader reader = new YamlReader();
        List<TSCreds> optCreds = reader.parseContrastYaml(contrastFile);
        assertTrue(!optCreds.isEmpty());
        TSCreds creds = optCreds.get(0);
        assertEquals("https://example.contrastsecurity.com/Contrast",creds.getUrl());
        assertEquals("aaabbbccc",creds.getApiKey());
        assertEquals("aaabbbcccddd",creds.getServiceKey());
        assertEquals("aaabbbccc@ContrastSecurity",creds.getUserName());
    }

}