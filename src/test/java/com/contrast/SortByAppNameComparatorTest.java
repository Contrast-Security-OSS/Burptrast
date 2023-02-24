package com.contrast;

import com.contrastsecurity.models.Application;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class SortByAppNameComparatorTest {

    @Test
    public void testWithApplicationList() {
        List<Application> applications = getApplicationList();
        applications.sort(new SortByAppNameComparator());
        assertEquals("AppA",applications.get(0).getName());
        assertEquals("AppB",applications.get(1).getName());
        assertEquals("AppC",applications.get(2).getName());

    }

    private List<Application> getApplicationList() {
        return Arrays.asList(getApplication("AppC",1l),getApplication("AppA",2l),getApplication("AppB",3l));
    }

    private Application getApplication(String appName, Long lastSeen) {
        Gson gson = new Gson();
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("name",appName);
        jsonObject.addProperty("last_seen",lastSeen);
        return gson.fromJson(jsonObject,Application.class);
    }

}