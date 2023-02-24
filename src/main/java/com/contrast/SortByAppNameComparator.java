package com.contrast;

import com.contrastsecurity.models.Application;

import java.util.Comparator;

public class SortByAppNameComparator implements Comparator<Application> {

    @Override
    public int compare(Application o1, Application o2) {
        return o1.getName().compareTo(o2.getName());
    }
}
