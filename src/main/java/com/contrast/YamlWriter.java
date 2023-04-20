package com.contrast;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;

public class YamlWriter {

    public void writeYamlFile(List<TSCreds> credsList, Path file) throws IOException {
        DumperOptions dumperOptions = new DumperOptions();
        dumperOptions.setPrettyFlow(true);
        Yaml yaml = new Yaml(dumperOptions);
        HashMap<String,Object> topLevel = new HashMap<>();
        int i=0;
        for(TSCreds cred : credsList) {

            HashMap<String,String> data = new HashMap<>();
            data.put("url",cred.getUrl());
            data.put("api_key",cred.getApiKey());
            data.put("service_key",cred.getServiceKey());
            data.put("user_name",cred.getUserName());
            data.put("org_id",cred.getOrg());
            if(i==0) {
                topLevel.put("api",data);
            } else {
                topLevel.put("api"+i,data);
            }

            i++;
        }
        String yamlData = yaml.dump(topLevel);
        Files.write(file,yamlData.getBytes());

    }





}
