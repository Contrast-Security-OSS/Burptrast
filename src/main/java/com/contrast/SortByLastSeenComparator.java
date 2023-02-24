package com.contrast;

import com.contrastsecurity.models.Application;

import java.util.Comparator;

public class SortByLastSeenComparator implements Comparator<Application> {
    @Override
    public int compare(Application o1, Application o2) {
        if(o1.getLastSeen() == o2.getLastSeen()) {
            return 0;
        } else if (o1.getLastSeen()> o2.getLastSeen()) {
            return -1;
        } else {
            return 1;
        }
    }
}
