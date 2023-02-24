package burp;

import com.contrastsecurity.models.Trace;

public class PathTracePair {
    private String path;
    private Trace trace;

    public PathTracePair(String path, Trace trace) {
        this.path = path;
        this.trace = trace;
    }

    public String getPath() {
        return path;
    }

    public Trace getTrace() {
        return trace;
    }
}
