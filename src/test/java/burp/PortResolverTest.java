package burp;

import org.junit.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.Assert.*;

public class PortResolverTest {

    @Test
    public void testWithEmptyPortAndHTTP() {
        setup("http","");
        assertEquals(80,PortResolver.getPort());
    }

    @Test
    public void testWithEmptyPortAndHTTPS() {
        setup("https","");
        assertEquals(443,PortResolver.getPort());
    }

    @Test
    public void testWithNonPortAndHTTPS() {
        setup("https","123");
        assertEquals(123,PortResolver.getPort());
    }

    @Test
    public void testWithNonEmptyPortAndHTTP() {
        setup("http","123");
        assertEquals(123,PortResolver.getPort());
    }

    private void setup(String protocol, String port) {
        Components.setProtocolCombo(new JComboBox<>());
        Components.getProtocolCombo().addItem("http");
        Components.getProtocolCombo().addItem("https");
        Components.getProtocolCombo().setSelectedItem(protocol);
        Components.setPortNumberField(new JTextField());
        Components.getPortNumberField().setText(port);
    }


}