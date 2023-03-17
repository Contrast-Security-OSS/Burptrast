package burp;

import com.contrast.threads.StoppableThread;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class ThreadManager implements IExtensionStateListener {


    private final ThreadPoolExecutor executor =
            (ThreadPoolExecutor) Executors.newFixedThreadPool(10);

    private static final Object lock = new Object();

    private List<StoppableThread> threadList = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void extensionUnloaded() {
        synchronized (lock) {
            threadList.forEach(StoppableThread::notifyThread);
        }
    }

    public void addToThreadList(StoppableThread thread) {
        synchronized (lock) {
            threadList.add(thread);
        }
    }

    public ThreadPoolExecutor getExecutor() {
        return executor;
    }
}
