package net.sf.jIPtables.connection;

import java.util.HashMap;
import java.util.Map;

/**
 * This task will be notified on connection events by netfilter
 */
class NetFilterConnTask extends Thread {

	Map<Long, Connection> connections = new HashMap<Long, Connection>();

	boolean terminate = false;
	
	static {
		System.loadLibrary("jiptables_conntrack");
	}
	
	
	public NetFilterConnTask() {
		start();
	}

	@Override
	public void run() {
		init();
	}

	/**
	 * Initialize the netfilter listener
	 */
	private native void init();
	
	/**
	 * Deinitialize the netfilter listener
	 */
	private native void deinit();

	/**
	 * @return Get the connection object associated to the specified id or
	 *         create a new one
	 */
	public Connection getConnection(String connectionID_s) {
		Long connectionID = Long.parseLong(connectionID_s);
		Connection conn = connections.get(connectionID);
		if (conn == null) {
			conn = new Connection(connectionID);
			connections.put(connectionID, conn);
		}
		return conn;
	}

	/**
	 * Called from native code for new connection notification
	 */
	private void notifyNewConnection(Object newConnection) {
		if (newConnection instanceof Connection)
			for (ConnectionListener l : ConnectionTracker.listeners)
				l.onConnectionStarted((Connection) newConnection);
	}

	/**
	 * Called from native code for updated connection notification
	 */
	private void notifyUpdatedConnection(Object updatedConnection) {
		if (updatedConnection instanceof Connection)
			for (ConnectionListener l : ConnectionTracker.listeners)
				l.onConnectionStateChanged((Connection) updatedConnection);
	}

	/**
	 * Called from native code for destroyed connection notification
	 */
	private void notifyDestroyedConnection(Object destroyedConnection) {
		if (!(destroyedConnection instanceof Connection))
			return;

		for (ConnectionListener l : ConnectionTracker.listeners)
			l.onConnectionTerminated((Connection) destroyedConnection);
		
		connections.remove(((Connection) destroyedConnection).getId());
	}

	/**
	 * Signal to unregister for notifications
	 */
	public void requestTerminate() {
		this.terminate = true;
	}

	/**
	 * @return True if this task is terminated or is terminating
	 */
	public boolean isTerminated() {
		return terminate;
	}
	
	
}