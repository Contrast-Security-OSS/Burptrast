package burp;



public class PortResolver {

    public static int getPort() {
        String textPort = Components.getPortNumberField().getText();
        if(textPort==null||textPort.isEmpty()) {
            String protocol = Components.getProtocolCombo().getSelectedItem().toString();
            if(protocol.equals("http")) {
                return 80;
            } else {
                return 443;
            }
        }
        return Integer.parseInt(textPort);
    }

}
