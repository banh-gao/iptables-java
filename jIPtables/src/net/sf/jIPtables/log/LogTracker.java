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

package net.sf.jIPtables.log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Listen on iptables log provided by netfilter. The type of log notified
 * depends on the NFLOG target rule specified in the iptables configuration.
 * 
 */
public class LogTracker {

	private final List<LogListener> listeners = new ArrayList<LogListener>();

	private static final Map<Integer, LogTracker> trackerInstances = new HashMap<Integer, LogTracker>();

	private NetFilterLogTask listenerTask;

	private int nfGroup;

	/**
	 * Get a log tracker, the netfilter group is set to the default group 0.
	 * All logs will be notified in cronological order.
	 */
	public static LogTracker getInstance() {
		return getInstance(0);
	}

	/**
	 * Get a log tracker that listen on the specified netfilter group.
	 * All logs will be notified in cronological order.
	 * 
	 * @param nfGroup
	 *            The netfilter group
	 */
	public static LogTracker getInstance(int nfGroup) {
		LogTracker t = trackerInstances.get(nfGroup);
		if (t == null) {
			t = new LogTracker(nfGroup);
			trackerInstances.put(nfGroup, t);
		}
		return t;
	}

	private LogTracker(int nfGroup) {
		this.nfGroup = nfGroup;
		listenerTask = new NetFilterLogTask(this, nfGroup);
		listenerTask.start();
	}

	/**
	 * @return The Netfilter group this log tracker is associated with
	 */
	public int getNFGroup() {
		return nfGroup;
	}

	/**
	 * Add a log listener that will be notified when a firewall log is notified
	 * 
	 * @throws NullPointerException
	 *             If the specified listener is null
	 */
	public void addLogListener(LogListener l) {
		if (l == null)
			throw new NullPointerException();
		listeners.add(l);
	}

	/**
	 * Remove a log listener
	 * 
	 * @throws NullPointerException
	 *             If the specified listener is null
	 */
	public void removeLogListener(LogListener l) {
		if (l == null)
			throw new NullPointerException();
		listeners.remove(l);
	}

	/**
	 * Notify the listeners for firewall logs (called from the listener task)
	 */
	void notifyNewLog(Packet e) {
		for (LogListener l : listeners)
			l.onNewLog(e);
	}

	@Override
	protected void finalize() throws Throwable {
		trackerInstances.remove(this);
		listenerTask.requestTerminate(true);
		super.finalize();
	}
}