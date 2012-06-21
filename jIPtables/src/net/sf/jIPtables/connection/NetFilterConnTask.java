/**
 * @package jIPtables
 * @copyright Copyright (C) 2011 jIPtables. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <zdenial@gmx.com>"
 * 
 *         This file is part of jIPtables.
 *         jIPtables is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         jIPtables is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 * 
 *         You should have received a copy of the GNU General Public License
 *         along with jIPtables. If not, see
 *         <http://www.gnu.org/licenses/>.
 * 
 */

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
		init();
	}

	@Override
	public void run() {
	}
	
	private void handleConnectionEvent() {
		
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

	// Called from native code for new connection notification
	private void notifyNewConnection(Object newConnection) {
		if (newConnection instanceof Connection) {
			for (ConnectionListener l : ConnTracker.connectionListeners)
				l.onConnectionStarted((Connection) newConnection);
		}
	}

	// Called from native code for updated connection notification
	private void notifyUpdatedConnection(Object updatedConnection) {
		if (updatedConnection instanceof Connection)
			for (ConnectionListener l : ConnTracker.connectionListeners)
				l.onConnectionStateChanged((Connection) updatedConnection);
	}

	// Called from native code for terminated connection notification
	private void notifyTerminatedConnection(Object terminatedConnection) {
		if (!(terminatedConnection instanceof Connection))
			return;

		for (ConnectionListener l : ConnTracker.connectionListeners)
			l.onConnectionTerminated((Connection) terminatedConnection);

		connections.remove(((Connection) terminatedConnection).getId());
	}

	/**
	 * Signal to unregister for notifications
	 */
	public void requestTerminate() {
		this.terminate = true;
	}

	/**
	 * @return True if this task is terminated or a termination request is
	 *         pending
	 */
	public boolean isTerminated() {
		return terminate;
	}

}