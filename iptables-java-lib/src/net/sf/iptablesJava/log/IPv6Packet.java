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
 * An IPv6 packet logged by the firewall
 */
public abstract class IPv6Packet extends Packet {

	private int totalLength;

	private int trafficClass;
	private int hopLimit;
	private long flowLabel;
	private int nexthdr;
	private int id;
	private int fragmentOffset;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("tc".equals(field))
			trafficClass = Integer.parseInt(value);
		else if ("hoplimit".equals(field))
			hopLimit = Integer.parseInt(value);
		else if ("tot_len".equals(field))
			totalLength = Integer.parseInt(value);
		else if ("flowlabel".equals(field))
			flowLabel = Long.parseLong(value);
		else if ("nexthdr".equals(field))
			nexthdr = Integer.parseInt(value);
		else if ("id".equals(field))
			id = Integer.parseInt(value);
		else if ("frag".equals(field))
			fragmentOffset = Integer.parseInt(value);
	}

	/**
	 * @return The length of payload in bytes, the next headers are also part of
	 *         the
	 *         payload
	 */
	public int getPayloadLength() {
		return totalLength;
	}

	/**
	 * @return The assigned traffic class
	 */
	public int getTrafficClass() {
		return trafficClass;
	}

	/**
	 * @return The hop limit of the IPv6 packet (commonly it corresponds to the
	 *         ttl
	 *         field in IPv4)
	 */
	public int getHopLimit() {
		return hopLimit;
	}

	/**
	 * @return The flow label
	 */
	public long getFlowLabel() {
		return flowLabel;
	}
	
	/**
	 * @return The protocol number of the next header
	 */
	public int getNextHeader() {
		return nexthdr;
	}
	
	/**
	 * @return The IP packet identification id used by the ip fragments
	 */
	public int getPacketId() {
		return id;
	}
	
	/**
	 * @return The fragment offset of an ip fragment packet
	 */
	public int getFragmentOffset() {
		return fragmentOffset;
	}
}
