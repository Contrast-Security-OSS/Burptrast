package burp;

import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.*;

public class RouteTableComparatorTest {


    @Test
    public void testWithTwoDatesSame() {
       Date date1 = new Date(123456l);
       Date date2 = new Date(123456l);
       DataModel datamodel = new DataModel();
       datamodel.getFormattedDateMap().put(date1.toString(),date1.getTime());
       datamodel.getFormattedDateMap().put(date2.toString(),date2.getTime());
       RouteTableComparator comparator = new RouteTableComparator(datamodel);
       assertEquals(0,comparator.compare(date1,date2));
    }

    @Test
    public void testWithFirstOlderThanSecond() {
        Date date1 = new Date(123456789l);
        Date date2 = new Date(1l);
        DataModel datamodel = new DataModel();
        datamodel.getFormattedDateMap().put(date1.toString(),date1.getTime());
        datamodel.getFormattedDateMap().put(date2.toString(),date2.getTime());
        RouteTableComparator comparator = new RouteTableComparator(datamodel);
        assertEquals(1,comparator.compare(date1.toString(),date2.toString()));
    }

    @Test
    public void testWithFirstYoungerThanSecond() {
        Date date1 = new Date(1l);
        Date date2 = new Date(123456789l);
        DataModel datamodel = new DataModel();
        datamodel.getFormattedDateMap().put(date1.toString(),date1.getTime());
        datamodel.getFormattedDateMap().put(date2.toString(),date2.getTime());
        RouteTableComparator comparator = new RouteTableComparator(datamodel);
        assertEquals(-1,comparator.compare(date1.toString(),date2.toString()));
    }

}