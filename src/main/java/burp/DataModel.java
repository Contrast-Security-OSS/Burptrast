package burp;

import com.contrast.SortType;
import com.contrast.TSCreds;
import com.contrast.model.Route;
import com.contrast.model.RouteCoverage;
import com.contrast.model.TraceIDDecoractedHttpRequestResponse;
import com.contrastsecurity.models.Application;
import com.contrastsecurity.models.Story;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;

import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.util.ArrayList;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class DataModel {

    private final Map<Route, Optional<RouteCoverage>> routeCoverageMap = new HashMap<>();
    private final List<TraceIDDecoractedHttpRequestResponse> vulnRequests = new ArrayList<>();

    private File credsFile;

    private Optional<TSCreds> credentials = Optional.empty();

    private final Map<String,String> appNameIDMap = new HashMap<>();
    private final List<Trace> traces = new ArrayList<>();
    private final Map<String, Long> formattedDateMap = new HashMap<>();

    private DefaultTableModel routeTableModel;

    private DefaultTableModel traceTableModel;

    private final Map<String,Long> appToServerMap = new HashMap<>();

    private final Map<String, StoryResponse> traceIDStoryMap = new HashMap<>();

    private final Map<String,Set<Trace>> nonRequestPathVulnMap = new HashMap<>();



    private SortType sortType = SortType.SORT_BY_NAME;


    private List<Application> applications = new ArrayList<>();

    public DataModel() {}

    public void clearData() {
        routeCoverageMap.clear();
        vulnRequests.clear();
        traces.clear();
        formattedDateMap.clear();
        clearRouteTable();
        clearTraceTable();
        traceIDStoryMap.clear();
        nonRequestPathVulnMap.clear();
    }

    /**
     * Clears the Route Table, called when a new application is selected in the application drop down.
     */
    public void clearRouteTable() {
        if(routeTableModel!=null) {
            routeTableModel.setRowCount(0);
        }
    }

    /**
     * Clears the Trace Table. This is called when a new Application is selected in the Application drop down.
     */
    public void clearTraceTable() {
        if(traceTableModel!=null) {
            traceTableModel.setRowCount(0);
        }
    }

    public Map<Route, Optional<RouteCoverage>> getRouteCoverageMap() {
        return routeCoverageMap;
    }

    public List<TraceIDDecoractedHttpRequestResponse> getVulnRequests() {
        return vulnRequests;
    }

    public File getCredsFile() {
        return credsFile;
    }

    public void setCredsFile(File credsFile) {
        setCredentials(Optional.empty());
        this.credsFile = credsFile;
    }

    public Map<String, String> getAppNameIDMap() {
        return appNameIDMap;
    }

    public List<Trace> getTraces() {
        return traces;
    }

    public Map<String, Long> getFormattedDateMap() {
        return formattedDateMap;
    }

    public DefaultTableModel getRouteTableModel() {
        return routeTableModel;
    }

    public void setRouteTableModel(DefaultTableModel routeTableModel) {
        this.routeTableModel = routeTableModel;
    }

    public DefaultTableModel getTraceTableModel() {
        return traceTableModel;
    }

    public void setTraceTableModel(DefaultTableModel traceTableModel) {
        this.traceTableModel = traceTableModel;
    }

    public Optional<TSCreds> getCredentials() {
        return credentials;
    }

    public void setCredentials(Optional<TSCreds> credentials) {
        this.credentials = credentials;
    }


    public Map<String, Long> getAppToServerMap() {
        return appToServerMap;
    }

    public SortType getSortType() {
        return sortType;
    }

    public void setSortType(SortType sortType) {
        this.sortType = sortType;
    }


    public List<Application> getApplications() {
        return applications;
    }

    public void setApplications(List<Application> applications) {
        this.applications = applications;
    }

    public Map<String, StoryResponse> getTraceIDStoryMap() {
        return traceIDStoryMap;
    }

    public Map<String, Set<Trace>> getNonRequestPathVulnMap() {
        return nonRequestPathVulnMap;
    }
}
