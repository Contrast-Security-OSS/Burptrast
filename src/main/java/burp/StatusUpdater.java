package burp;


/**
 * Tracks the current status of Burptrast. Due to multiple threads updating the same underlying status it uses a simple
 * count to work out the status as a thread starts it calls updateStatus(LOADING), which increments the loadingCount.
 * When a subsequent call of updateStatus(READY) is made, it decrements the count. A count of 0 means ready and >0 means
 * loading.
 * When loading it will change the text of the status field int the UI to "loading" and disable all buttons. This
 * ensures we don't get into a weird state where half way through processing traces, we change the underlying
 * application or org.
 * Once the status changes back to ready and therefore there are no running threads, the ui is reenabled.
 *
 *
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
                Components.setButtons(true);
                dataModel.setStatus(Status.ERROR);
                Components.getStatusLabel().setText(Status.ERROR.getStatus());
                Components.getStatusLabel().updateUI();
            }
            if(dataModel.getStatus()!=null&&!dataModel.getStatus().equals(Status.ERROR)) {
                if(status.equals(Status.LOADING)) {
                    loadingCount++;
                }
                if(status.equals(Status.READY)) {
                    loadingCount--;
                }
                if(loadingCount>0) {
                    Components.setButtons(false);
                    dataModel.setStatus(Status.LOADING);
                    Components.getStatusLabel().setText(Status.LOADING.getStatus());
                    Components.getStatusLabel().updateUI();
                } else {
                    Components.setButtons(true);
                    dataModel.setStatus(Status.READY);
                    Components.getStatusLabel().setText(Status.READY.getStatus());
                    Components.getStatusLabel().updateUI();
                }
            }
        }
    }



}
