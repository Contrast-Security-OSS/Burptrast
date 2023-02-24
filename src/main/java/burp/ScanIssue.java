package burp;

import com.contrast.HTMLSanitiser;
import com.contrast.Logger;
import com.contrast.RequestResponseGenerator;
import com.contrast.TSCreds;
import com.contrast.TSVulnLinkGenerator;
import com.contrast.mapper.ConfidenceMapper;
import com.contrast.mapper.IssueTypeMapper;
import com.contrast.mapper.SeverityMapper;
import com.contrastsecurity.models.Chapter;
import com.contrastsecurity.models.StoryResponse;
import com.contrastsecurity.models.Trace;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

public class ScanIssue implements IScanIssue
{

    private final IHttpRequestResponse requestResponse;
    private final Optional<Trace> trace;
    private final Logger logger;
    private final StoryResponse response;
    private final TSCreds creds;
    private final String orgID;
    private final String appID;

    public ScanIssue(IHttpRequestResponse requestResponse, Optional<Trace> trace, Logger logger, StoryResponse response, TSCreds creds, String orgID, String appID) {
        this.requestResponse = requestResponse;
        this.trace = trace;
        this.logger = logger;
        this.response = response;
        this.creds = creds;
        this.orgID = orgID;
        this.appID = appID;
    }

    @Override
    public URL getUrl() {
        try {
            return new RequestResponseGenerator().getURLFromHttpReq(requestResponse);
        } catch (MalformedURLException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public String getIssueName() {
        if(trace.isPresent()) {
            return trace.get().getTitle();
        } else {
            return "Unknown";
        }

    }

    @Override
    public int getIssueType() {
        String id = "UNKNOWN";
        if(trace.isPresent()) {
            id = trace.get().getRule();
        }
        return IssueTypeMapper.getIssueType(id,logger).getBurpType();
    }

    @Override
    public String getSeverity() {
        if(trace.isPresent()) {
            return SeverityMapper.getMappingForContrast(trace.get().getSeverity()).getBurpSeverity();
        } else {
            return "Note";
        }
    }

    @Override
    public String getConfidence() {
        if(trace.isPresent()) {
            return ConfidenceMapper.getMappingForContrast(trace.get().getLikelihood()).getBurpConfidence();
        } else {
            return "Tentative";
        }
    }

    @Override
    public String getIssueBackground() {
        if(response!=null&& response.getStory()!=null&& response.getStory().getRisk()!=null&& response.getStory().getRisk().getText()!=null) {
            return response.getStory().getRisk().getText();
        } else {
            return null;
        }
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        StringBuilder msg = new StringBuilder();
        if(trace.isPresent()) {
            String vulnTSURL = new TSVulnLinkGenerator().getURLAHref(creds.getUrl(),orgID,appID,trace.get().getUuid());
            msg.append(vulnTSURL+"<br />");

        }
        if(response!=null&&response.getStory()!=null&& response.getStory().getChapters()!=null) {
            for(Chapter chapter : response.getStory().getChapters()) {
                msg.append("<b>");
                if(chapter.getType()!=null) {
                    if(chapter.getType().equals("properties")) {
                        msg.append("source");
                    } else {
                        msg.append(chapter.getType());
                    }
                    msg.append("</b>");
                    msg.append("<br />");
                }
                if(chapter.getIntroText()!=null) {
                    msg.append(chapter.getIntroText());
                    msg.append("<br />");
                }
                if(chapter.getBody()!=null) {
                    msg.append(chapter.getBody());
                    msg.append("<br />");
                }
            }
        }
        return new HTMLSanitiser().sanitiseHTML(msg.toString());
    }


    @Override
    public String getRemediationDetail() {
        return trace.map(value -> new TSVulnLinkGenerator().getRemediationLink(creds.getUrl(), orgID, appID, value.getUuid())).orElse(null);
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{requestResponse};
    }

    @Override
    public IHttpService getHttpService() {
        return requestResponse.getHttpService();
    }
}
