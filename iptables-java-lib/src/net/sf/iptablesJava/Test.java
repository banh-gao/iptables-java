/**
 * @package iptables-java
 * @copyright Copyright (C) 2011 iptables-java. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <zdenial@gmx.com>"
 * 
 *         This file is part of iptables-java.
 *         iptables-java is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         iptables-java is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 * 
 *         You should have received a copy of the GNU General Public License
 *         along with iptables-java. If not, see
 *         <http://www.gnu.org/licenses/>.
 * 
 */

package net.sf.iptablesJava;

import net.sf.iptablesJava.connection.ConnTracker;
import net.sf.iptablesJava.connection.Connection;
import net.sf.iptablesJava.connection.ConnectionListener;
import net.sf.iptablesJava.log.LogListener;
import net.sf.iptablesJava.log.LogTracker;
import net.sf.iptablesJava.log.Packet;

public class Test {

	public static void main(String[] args) {
		System.out.println(System.getProperty("java.library.path"));
		testLog();
	}

	private static void testLog() {
		LogTracker t = LogTracker.getInstance();

		t.addLogListener(new LogListener() {

			@Override
			public void onNewLog(Packet newPacket) {
				System.out.println(newPacket);
			}
		});
	}

	private static void testConn() {
		ConnTracker.addConnectionListener(new ConnectionListener() {

			@Override
			public void onConnectionTerminated(Connection terminatedConnection) {
				System.out.println("TER: " + terminatedConnection);
			}

			@Override
			public void onConnectionStateChanged(Connection changedConnection) {
				System.out.println("CHG: " + changedConnection);
			}

			@Override
			public void onConnectionStarted(Connection startedConnection) {
				System.out.println("NEW: " + startedConnection);
			}
		});
	}
}
