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

package net.sf.iptablesJava.log;

/**
 * This class is the interface between java code and low level library, log events are notified to the associated log tracker
 * 
 */
class NetFilterLogTask {

	private final LogTracker logTracker;
	private final int nfGroup;

	private boolean terminate = false;

	static {
		System.loadLibrary("iptables-java");
	}

	NetFilterLogTask(LogTracker logTracker, int nfGroup) {
		this.logTracker = logTracker;
		this.nfGroup = nfGroup;
	}

	public void requestTerminate(boolean terminate) {
		this.terminate = terminate;
	}

	native void init(int group) throws InitializationException;

	/**
	 * @param protocol
	 *            the L4 protocol to build a specific packet implementation
	 * @return A new packet object for the native code
	 * 
	 */
	Packet buildNewPacket(String protocol) {
		return Packet.getPacket(protocol);
	}

	/**
	 * Called from the native code to send notification
	 * 
	 * @param packet
	 */
	void notifyNewPacket(Object packet) {
		if (!(packet instanceof Packet))
			return;
		((Packet) packet).nfGroup = nfGroup;
		this.logTracker.notifyNewLog((Packet) packet);
	}
}