package burp;


import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Tracks the current status of Burptrast. Due to multiple threads updating the same underlying status it uses a simple
 * count to work out the status as a thread starts it calls updateStatus(LOADING), which increments the loadingCount.
 * When a subsequent call of updateStatus(READY) is made, it decrements the count. A count of 0 means ready and >0 means
 * loading.
 * When loading it will change the text of the status field int the UI to "loading" and disable all buttons. This
 * ensures we don't get into a weird state where halfway through processing traces, we change the underlying
 * application or org.
 * Once the status changes back to ready and therefore there are no running threads, the ui is reenabled.
 *
 */
public class StatusUpdater {

    private static final Object lock = new Object();

    private static int loadingCount = 0;

    public static void updateStatus(Status status,DataModel dataModel) {
        synchronized (lock) {
            if(dataModel.getStatus()==null) {
                dataModel.setStatus(status);
            }
            if(status.equals(Status.ERROR)) {
                if(loadingCount>0) {
                    loadingCount--;
                }
                Components.setButtons(true);
                setStatus(status,dataModel);
                setStatusBorder(Color.RED);
            }

            if(status.equals(Status.LOADING)) {
                loadingCount++;
            }
            if(status.equals(Status.READY)) {
                loadingCount--;
            } else if(status.equals((Status.AWAITING_CREDENTIALS))) {
                loadingCount--;
            }
            if(loadingCount>0) {
                Components.setButtons(false);
                setStatus(Status.LOADING,dataModel);
                setStatusBorder(Color.LIGHT_GRAY);
            } else if(status.equals(Status.READY)){
                Components.setButtons(true);
                Components.getCredsFile().setEnabled(true);
                Components.getSaveCredsFile().setEnabled(true);
                setStatus(status,dataModel);
                setStatusBorder(Color.GREEN);
            } else if(status.equals(Status.AWAITING_CREDENTIALS)){
                Components.getCredsFile().setEnabled(true);
                setStatus(status,dataModel);
                setStatusBorder(Color.LIGHT_GRAY);
            }
        }

    }

    private static void setStatus(Status status, DataModel dataModel) {
        dataModel.setStatus(status);
        Components.getStatusLabel().setText(status.getStatus());
        Components.getStatusLabel().updateUI();
        Components.getCredentialsStatusLabel().setText(status.getStatus());
        Components.getCredentialsStatusLabel().updateUI();

    }

    private static void setStatusBorder(Color color) {
        LineBorder lb = new LineBorder(color);
        Components.getCredentialsStatusPanel().setBorder(
                BorderFactory.createTitledBorder(lb, "Status", TitledBorder.CENTER, TitledBorder.TOP, null, null));
        Components.getStatusPanel().setBorder(
                BorderFactory.createTitledBorder(lb, "Status", TitledBorder.CENTER, TitledBorder.TOP, null, null));
    }

}
