package burp;

import java.util.Comparator;

public class RouteTableComparator implements Comparator<Object> {

    private final DataModel dataModel;

    public RouteTableComparator(DataModel dataModel) {
        this.dataModel = dataModel;
    }

    @Override
    public int compare(Object o1, Object o2) {
        long oneLong = getTimeStampFromDate(o1);
        long twoLong = getTimeStampFromDate(o2);
        if(oneLong>twoLong) {
            return 1;
        } else if(oneLong<twoLong) {
            return -1;
        } else {
            return 0;
        }
    }

    private long getTimeStampFromDate(Object object) {
        if("".equals(object)) {
            return Long.MIN_VALUE;
        } else if(object!=null&& dataModel.getFormattedDateMap().containsKey(object)){
            return dataModel.getFormattedDateMap().get(object);
        } else {
            return Long.MIN_VALUE;
        }
    }


}
