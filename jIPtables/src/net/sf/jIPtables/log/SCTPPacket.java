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

/**
 * A SCTP packet logged by the firewall
 */
public class SCTPPacket extends IPv4Packet {

	private int sport;
	private int dport;
	private long checksum;
	
	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("spt".equals(field))
			sport = Integer.parseInt(value);
		else if ("dpt".equals(field))
			dport = Integer.parseInt(value);
		else if ("sctp_sum".equals(field))
			checksum = Long.parseLong(value);
	}

	/**
	 * @return The source port
	 */
	public int getSourcePort() {
		return sport;
	}

	/**
	 * @return The destination port
	 */
	public int getDestinationPort() {
		return dport;
	}
	
	/**
	 * @return The SCTP checksum
	 */
	public long getChecksum() {
		return checksum;
	}

	@Override
	public String toString() {
		return "SCTPPacket [sport=" + sport + ", dport=" + dport + ", checksum=" + checksum + ", toString()=" + super.toString() + "]";
	}
}
