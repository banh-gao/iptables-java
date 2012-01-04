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

package net.sf.jIPtables.log;

/**
 * This thread listens to netfilter log notifications and notifies the java
 * registered log listeners
 * 
 */
class NetFilterLogTask extends Thread {

	private final LogTracker logTracker;
	private final int nfGroup;

	private boolean terminate = false;

	static {
		System.loadLibrary("jiptables_log");
	}

	NetFilterLogTask(LogTracker logTracker, int nfGroup) {
		this.logTracker = logTracker;
		this.nfGroup = nfGroup;
	}

	@Override
	public void run() {
		init(nfGroup);
		while (!terminate) {
			receiveNewPacket();
		}
	}

	public void requestTerminate(boolean terminate) {
		this.terminate = terminate;
	}

	private native void receiveNewPacket();

	private native void init(int group);

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