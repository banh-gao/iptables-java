/**
 * @package jIPtables
 * @copyright Copyright (C) 2011 jIPtables. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <daniel.zozin@gmail.com>"
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

import java.util.ArrayList;
import java.util.List;

/**
 * Track the connections activity and notify the listeners for connection events
 * 
 */
public class ConnectionTracker {

	/**
	 * Registered connection listeners
	 */
	static final List<ConnectionListener> listeners = new ArrayList<ConnectionListener>();

	private static NetFilterConnTask listenerTask = new NetFilterConnTask();

	/**
	 * Add a connection listener that will be notified when a connection event
	 * happen
	 * 
	 * @throws NullPointerException
	 *             If the specified listener is null
	 */
	public static synchronized void addConnectionListener(ConnectionListener l) {
		if (l == null)
			throw new NullPointerException();
		listeners.add(l);

		if (listenerTask.isTerminated()) {
			listenerTask = new NetFilterConnTask();
		}
	}

	/**
	 * Remove a connection listener
	 * 
	 * @throws NullPointerException
	 *             If the specified listener is null
	 */
	public static synchronized void removeConnectionListener(ConnectionListener l) {
		if (l == null)
			throw new NullPointerException();
		listeners.remove(l);
		if (listeners.size() == 0)
			listenerTask.requestTerminate();
	}
}