package burp;

public enum Status {

    READY(" Ready "),
    LOADING("Loading"),
    ERROR(" Error ");

    private final String status;

    Status(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }


}
