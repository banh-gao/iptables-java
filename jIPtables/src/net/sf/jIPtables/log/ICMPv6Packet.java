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
 * An ICMPv6 packet logged by the firewall
 */
public class ICMPv6Packet extends IPv6Packet {

	private int type;
	private int code;
	private int echoid;
	private int echoseq;
	private long checksum;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("type".equals(field))
			type = Integer.parseInt(value);
		else if ("code".equals(field))
			code = Integer.parseInt(value);
		else if ("echo_id".equals(field))
			echoid = Integer.parseInt(value);
		else if ("echo_seq".equals(field))
			echoseq = Integer.parseInt(value);
		else if ("icmpv6_sum".equals(field))
			checksum = Long.parseLong(value);
	}

	/**
	 * @return The ICMPv6 Message Type
	 */
	public int getType() {
		return type;
	}

	/**
	 * @return The ICMPv6 Message Subtype
	 */
	public int getCode() {
		return code;
	}

	/**
	 * @return The ICMPv6 echo ID
	 */
	public int getEchoId() {
		return echoid;
	}

	/**
	 * @return The ICMPv6 echo sequence number
	 */
	public int getEchoSeq() {
		return echoseq;
	}
	
	/**
	 * @return The ICMPv6 checksum
	 */
	public long getChecksum() {
		return checksum;
	}

	@Override
	public String toString() {
		return "ICMPv6Packet [type=" + type + ", code=" + code + ", echoid=" + echoid + ", echoseq=" + echoseq + ", checksum=" + checksum + ", toString()=" + super.toString() + "]";
	}
}
