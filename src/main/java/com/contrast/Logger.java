package com.contrast;

import java.io.PrintWriter;
import java.util.Date;

/**
 * Logger class, outputs to Burp's StdOut/StdErr. Which depending on how Burp is configured will appear in the Burp
 * Extension output tab, a log file on disk or to the Burp Process's console.
 * Where it is outputted is configured by Burp in the Extension tab.
 */
public class Logger {

    private final PrintWriter stdOut;
    private final PrintWriter stdErr;

    public Logger(PrintWriter stdOut, PrintWriter stdErr) {
        this.stdOut = stdOut;
        this.stdErr = stdErr;
    }

    public void logMessage(String message) {
        stdOut.println(getTimeStamp()+" : " +message);
    }

    private String getTimeStamp() {
        return new Date().toString();
    }

    public void logError(String error) {
        stdErr.println(getTimeStamp()+" : " +error);
    }

    public void logException(String error, Exception e) {
        stdErr.println(getTimeStamp()+" : " +error);
        e.printStackTrace(stdErr);
    }




}
