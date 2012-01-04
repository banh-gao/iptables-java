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

/**
 * Receive notifications for conntrack connection events
 * 
 */
public interface ConnectionListener {

	/**
	 * Called when the connection state changes
	 * 
	 * @param connection
	 *            The connection that changes
	 */
	public void onConnectionStateChanged(Connection connection);

	/**
	 * Called when a new connection is started
	 * 
	 * @param connection
	 *            The started connection
	 */
	public void onConnectionStarted(Connection connection);

	/**
	 * Called when a connection is terminated
	 * 
	 * @param connection
	 *            The terminated connection
	 */
	public void onConnectionTerminated(Connection connection);
}
