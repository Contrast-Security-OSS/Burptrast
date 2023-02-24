package com.contrast;

public class TSVulnLinkGenerator {

    public String getURL(String tsURL,String orgID,String applicationID,String vulnID) {
        return new HTMLSanitiser().sanitiseHTML(
                String.format("%s/static/ng/index.html#/%s/applications/%s/vulns/%s",tsURL,orgID,applicationID,vulnID)
        );
    }

    public String getURLAHref(String tsURL,String orgID,String applicationID,String vulnID) {
        String url = getURL(tsURL,orgID,applicationID,vulnID);
        return new HTMLSanitiser().sanitiseHTML(
                String.format("<a href=\""+url+"\">Vulnerability Details</a>")
        );
    }

    public String getRemediationLink(String tsURL,String orgID,String applicationID,String vulnID) {
        String url = getURL(tsURL,orgID,applicationID,vulnID);
        return new HTMLSanitiser().sanitiseHTML(
                String.format("<a href=\""+url+"/recommendation"+"\">Remediation Details</a>")
        );
    }


}
