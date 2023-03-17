package burp;


import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


/**
 * The CorrelationIDAppender is used to append an HTTP Header to every request made via Burptrast when Live Browse is
 * enabled. This ID is looked for when new vulnerabilities are found by Assess. Where this ID is found in the http
 * request that triggered that vuln, we can correlate that back to this session and live update the vuln tab.
 */
public class CorrelationIDAppender implements IHttpListener {

    private final String correlationHeader;

    private final UUID correlationID;
    private final IBurpExtenderCallbacks callbacks;

    public static final String NAME = "Burptrast-Correlation-Id";


    public CorrelationIDAppender(IBurpExtenderCallbacks callbacks) {
        correlationID = UUID.randomUUID();
        correlationHeader = NAME+":"+ correlationID;
        this.callbacks = callbacks;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(messageIsRequest) {
            IRequestInfo rqInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
            List<String> headers = new ArrayList<>(rqInfo.getHeaders());
            List<String> headersToRemove = new ArrayList<>();
            for(String header : headers) {
                if(header.contains(NAME)) {
                    if(header.equals(correlationHeader)) {
                        break;
                    } else {
                        headersToRemove.add(header);
                    }
                }
            }
            headers.removeAll(headersToRemove);
            headers.add(correlationHeader);
            String body = new String(messageInfo.getRequest()).substring(rqInfo.getBodyOffset());
            byte[] msg = callbacks.getHelpers().buildHttpMessage(headers, body.getBytes());
            messageInfo.setRequest(msg);
        }
    }

    public String getHeaderNameValue() {
        return correlationHeader;
    }

    public UUID getCorrelationID() {
        return correlationID;
    }


}
