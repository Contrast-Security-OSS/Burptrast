package com.contrast;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

/**
 * Used to sanitise the HTML. Burp already limits what HTML tags that can be rendered. But as we are only using 3 tags
 * br,b and a.
 * This sanitiser will remove any other HTML tags. This allows us to limit the risk of an XSS attack.
 */
public class HTMLSanitiser {

    public String sanitiseHTML(String html) {
        PolicyFactory policyBuilder = new HtmlPolicyBuilder()
                .allowAttributes("src").onElements("img")
                .allowAttributes("href").onElements("a")
                .allowStandardUrlProtocols()
                .allowElements(
                        "a", "br", "b"
                ).toFactory();
        return policyBuilder.sanitize(html);
    }

}
