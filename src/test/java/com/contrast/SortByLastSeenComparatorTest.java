package com.contrast;

import com.contrastsecurity.models.Application;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class SortByLastSeenComparatorTest {


    @Test
    public void testWithApplicationList() {
        List<Application> applications = getApplicationList();
        applications.sort(new SortByLastSeenComparator());
        assertEquals("appthree",applications.get(0).getName());
        assertEquals("apptwo",applications.get(1).getName());
        assertEquals("appone",applications.get(2).getName());

    }

    private List<Application> getApplicationList() {
        return Arrays.asList(getApplication("appone",1l),getApplication("apptwo",2l),getApplication("appthree",3l));
    }

    private Application getApplication(String appName, Long lastSeen) {
        Gson gson = new Gson();
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("name",appName);
        jsonObject.addProperty("last_seen",lastSeen);
        return gson.fromJson(jsonObject,Application.class);
    }

}