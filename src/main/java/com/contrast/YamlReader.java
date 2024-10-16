package com.contrast;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reads the credentials file, this file contains the credentials required to authenticate with the TeamServer.
 * The credentials file has the format.
 * api:
 *   url: https://example.contrastsecurity.com/Contrast
 *   api_key: aaabbbccc
 *   service_key: aaabbbcccddd
 *   user_name: aaabbbccc@OrgName
 *
 */
public class YamlReader {

    public List<TSCreds> parseContrastYaml(File contrastFile) throws IOException {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        List<TSCreds> credList = new ArrayList<>();
        try(FileInputStream fis = new FileInputStream(contrastFile)) {
            Map<String,Object> results = yaml.load(fis);
            if(results.containsKey("api")&&results.get("api")!=null) {
                credList.add(getCredFromMap((Map<String, Object>) results.get("api")));
                for(String resultKey : results.keySet()) {
                    if(resultKey!=null&&resultKey.startsWith("api")&&!resultKey.equals("api")) {
                        Map<String, Object> resultObject = (Map<String, Object>) results.get(resultKey);
                        credList.add(getCredFromMap(resultObject));
                    }
                }


            } else {
                return credList;
            }
        }
        return credList;
    }

    private TSCreds getCredFromMap(Map<String,Object> resultMap) {
        return new TSCreds(getResultFromObject(resultMap.get("url")),getResultFromObject(resultMap.get("api_key")),
                getResultFromObject(resultMap.get("service_key")),getResultFromObject(resultMap.get("user_name")),getResultFromObject(resultMap.get("org_id")));
    }


    private String getResultFromObject(Object result) {
        if(result == null) {
            return "";
        } else {
            return result.toString();
        }
    }


}
