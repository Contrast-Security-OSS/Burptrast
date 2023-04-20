package com.contrast;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class YamlWriterTest {


    @Test
    public void writeWithSingleCred() throws IOException {
        Path tmpYamlFile = getTmpYamlFile();
        try {
            TSCreds creds = new TSCreds("https://example.contrast.com/Contrast", "AAABBBCCC", "DDDEEEFFF", "example@example.com", "GGGHHHIII");
            YamlWriter writer = new YamlWriter();
            writer.writeYamlFile(Collections.singletonList(creds),tmpYamlFile);
            assertTrue(tmpYamlFile.toFile().exists());
            assertTrue(tmpYamlFile.toFile().length()>0);
            YamlReader reader = new YamlReader();
            List<TSCreds> readCreds = reader.parseContrastYaml(tmpYamlFile.toFile());
            assertTrue(!readCreds.isEmpty());
            assertTrue(creds.equals(readCreds.get(0)));
        } finally {
            if(tmpYamlFile!=null&&tmpYamlFile.toFile().exists()) {
                tmpYamlFile.toFile().delete();
            }
        }

    }

    @Test
    public void writeWithMultipleOrgs() throws IOException {
        Path tmpYamlFile = getTmpYamlFile();
        try {
            TSCreds creds = new TSCreds("https://example.contrast.com/Contrast", "AAABBBCCC", "DDDEEEFFF", "example@example.com", "GGGHHHIII");
            TSCreds creds2 = new TSCreds("https://example.contrast.com/Contrast", "DFKJDFKJDFK3", "DDDFFFGGGHHH", "example@example.com", "DFDFDFDFDF");

            YamlWriter writer = new YamlWriter();
            writer.writeYamlFile(Arrays.asList(creds,creds2),tmpYamlFile);
            assertTrue(tmpYamlFile.toFile().exists());
            assertTrue(tmpYamlFile.toFile().length()>0);
            YamlReader reader = new YamlReader();
            List<TSCreds> readCreds = reader.parseContrastYaml(tmpYamlFile.toFile());
            assertEquals(2,readCreds.size());
            assertTrue(creds.equals(readCreds.get(0)));
            assertTrue(creds2.equals(readCreds.get(1)));
        } finally {
            if(tmpYamlFile!=null&&tmpYamlFile.toFile().exists()) {
                tmpYamlFile.toFile().delete();
            }
        }

    }


    private Path getTmpYamlFile() throws IOException {
        return Files.createTempFile("yamlwritertest","yaml");
    }


}