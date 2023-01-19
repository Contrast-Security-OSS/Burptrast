package com.contrast;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class YamlReader {



    public Optional<TSCreds> parseContrastYaml(File contrastFile) throws IOException {
        Yaml yaml = new Yaml();
        try(FileInputStream fis = new FileInputStream(contrastFile)) {
            Map<String,Object> results = yaml.load(fis);
            if(results.containsKey("api")&&results.get("api")!=null) {
                Map<String, Object> credObect = (Map<String, Object>) results.get("api");
                return Optional.of(new TSCreds(credObect.get("url").toString(),credObect.get("api_key").toString(),
                        credObect.get("service_key").toString(),credObect.get("user_name").toString()));
            } else {
                Optional.empty();
            }
        }
        return Optional.empty();
    }



}
