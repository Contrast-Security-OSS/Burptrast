package com.contrast;

import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Optional;

import static org.junit.Assert.*;

public class YamlReaderTest {


    @Test
    public void testWithValidYaml() throws IOException, URISyntaxException {
        File contrastFile = new File(YamlReaderTest.class.getResource("/contrast_security.yaml").toURI());
        YamlReader reader = new YamlReader();
        Optional<TSCreds> optCreds = reader.parseContrastYaml(contrastFile);
        assertTrue(optCreds.isPresent());
        TSCreds creds = optCreds.get();
        assertEquals("https://example.contrastsecurity.com/Contrast",creds.getUrl());
        assertEquals("aaabbbccc",creds.getApiKey());
        assertEquals("aaabbbcccddd",creds.getServiceKey());
        assertEquals("aaabbbccc@ContrastSecurity",creds.getUserName());
    }

}