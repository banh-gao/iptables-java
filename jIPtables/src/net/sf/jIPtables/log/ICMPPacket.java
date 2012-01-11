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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * An ICMP packet logged by the firewall
 */
public class ICMPPacket extends IPv4Packet {

	private int type;
	private int code;
	private int echoid;
	private int echoseq;
	private Inet4Address gateway;
	private long mtu;
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
		else if ("gateway".equals(field))
			gateway = parseGateway(value);
		else if ("mtu".equals(field))
			mtu = Long.parseLong(value);
		else if ("icmp_sum".equals(field))
			checksum = Long.parseLong(value);
		
	}

	private Inet4Address parseGateway(String rawData) {
		InetAddress gw = null;
		try {
			gw = InetAddress.getByName(getValue(rawData, "GATEWAY"));
			if (gw instanceof Inet4Address)
				return (Inet4Address) gw;
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @return The ICMP Message Type
	 */
	public int getType() {
		return type;
	}

	/**
	 * @return The ICMP Message Subtype
	 */
	public int getCode() {
		return code;
	}

	/**
	 * @return The ICMP echo ID used in echo request and reply messages
	 */
	public int getEchoId() {
		return echoid;
	}

	/**
	 * @return The ICMP echo sequence number used in echo request and reply
	 *         messages
	 */
	public int getEchoSequence() {
		return echoseq;
	}

	/**
	 * @return The ICMP gateway IP address used in redirect messages
	 */
	public Inet4Address getGateway() {
		return gateway;
	}

	/**
	 * @return The Maximum Transmission Unit in bytes used in destination
	 *         unreachable messages
	 */
	public long getMtu() {
		return mtu;
	}
	
	/**
	 * @return The ICMP checksum
	 */
	public long getChecksum() {
		return checksum;
	}

	@Override
	public String toString() {
		return "ICMPPacket [type=" + type + ", code=" + code + ", echoid=" + echoid + ", echoseq=" + echoseq + ", gateway=" + gateway + ", mtu=" + mtu + ", checksum=" + checksum + ", toString()=" + super.toString() + "]";
	}
}
