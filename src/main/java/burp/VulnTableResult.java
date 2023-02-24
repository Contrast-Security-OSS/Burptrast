package burp;

class VulnTableResult {

    private String url;
    private String verb;

    public VulnTableResult(String url, String verb) {
        this.url = url;
        this.verb = verb;
    }

    public String getUrl() {
        return url;
    }

    public String getVerb() {
        return verb;
    }
}
