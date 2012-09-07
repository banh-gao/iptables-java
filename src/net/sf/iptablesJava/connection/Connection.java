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

package net.sf.iptablesJava.connection;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Represent a bidirectional connection
 * 
 */
public class Connection {

	enum NetworkProtocol {
		IPv4(2), IPv6(41);

		private final int protocolNum;

		private NetworkProtocol(int protocolNum) {
			this.protocolNum = protocolNum;
		}

		public static NetworkProtocol valueOf(int l3ProtoNum) {
			for (NetworkProtocol p : values()) {
				if (p.protocolNum == l3ProtoNum)
					return p;
			}
			return null;
		}
	}

	enum TransportProtocol {
		ICMP(1),
		IGMP(2),
		TCP(6),
		UDP(17),
		DCCP(33),
		GRE(47),
		ICMPv6(58),
		SCTP(132),
		UDP_LITE(136);

		private final int protocolNum;

		private TransportProtocol(int protocolNum) {
			this.protocolNum = protocolNum;
		}

		public static TransportProtocol valueOf(int l4ProtoNum) {
			for (TransportProtocol p : values()) {
				if (p.protocolNum == l4ProtoNum)
					return p;
			}
			return null;
		}
	}

	private NetworkProtocol networkProtocol;
	private TransportProtocol transportProtocol;
	private int l4protocolNum;

	private InetAddress srcAddr;
	private InetAddress dstAddr;

	private int srcPort;
	private int dstPort;

	private long origBytes;
	private long origPackets;

	private long replyBytes;
	private long replyPackets;

	private long mark;

	String state;
	long timeout;
	private long id;

	protected Connection(long id) {
		this.id = id;
	}

	// Used by the native code to set this object fields
	void setField(String field, String value) {
		if ("l3protoNum".equals(field))
			networkProtocol = NetworkProtocol.valueOf(Integer.parseInt(value));
		else if ("l4protoNum".equals(field))
			transportProtocol = TransportProtocol.valueOf(Integer.parseInt(value));
		else if ("src".equals(field))
			srcAddr = parseAddress(value);
		else if ("dst".equals(field))
			dstAddr = parseAddress(value);
		else if ("sport".equals(field))
			srcPort = Integer.parseInt(value);
		else if ("dport".equals(field))
			dstPort = Integer.parseInt(value);
		else if ("origBytes".equals(field))
			origBytes = Long.parseLong(value);
		else if ("origPackets".equals(field))
			origPackets = Long.parseLong(value);
		else if ("replyBytes".equals(field))
			replyBytes = Long.parseLong(value);
		else if ("replyPackets".equals(field))
			replyPackets = Long.parseLong(value);
		else if ("mark".equals(field))
			mark = Long.parseLong(value);
		else if ("timeout".equals(field))
			timeout = Long.parseLong(value);
		else if ("state".equals(field))
			state = value;
	}

	private static InetAddress parseAddress(String addr) {
		try {
			return InetAddress.getByName(addr);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * @return The layer 3 protocol
	 */
	public NetworkProtocol getNetworkProtocol() {
		return networkProtocol;
	}

	/**
	 * @return The layer 4 protocol
	 */
	public TransportProtocol getTransportProtocol() {
		return transportProtocol;
	}

	public InetAddress getDestinationAddress() {
		return dstAddr;
	}

	public InetAddress getSourceAddress() {
		return srcAddr;
	}

	public int getDestinationPort() {
		return dstPort;
	}

	public int getSourcePort() {
		return srcPort;
	}

	/**
	 * @return The conntrack connection ID
	 */
	public long getId() {
		return id;
	}

	public String getState() {
		return state;
	}

	public long getTimeout() {
		return timeout;
	}

	/**
	 * @return The mark of this connection applied from iptables using MARK
	 *         target
	 */
	public long getMark() {
		return mark;
	}

	/**
	 * @return The number of bytes sent by the connection originator
	 */
	public long getOrigBytesCount() {
		return origBytes;
	}

	/**
	 * @return The number of packets sent by the connection originator
	 */
	public long getOrigPacketsCount() {
		return origPackets;
	}

	/**
	 * @return The number of bytes sent by the connection replier
	 */
	public long getReplyBytesCount() {
		return replyBytes;
	}

	/**
	 * @return The number of packets sent by the connection replier
	 */
	public long getReplyPacketsCount() {
		return replyPackets;
	}

	@Override
	public String toString() {
		return "Connection [networkProtocol=" + networkProtocol + ", transportProtocol=" + transportProtocol + ", l4protocolNum=" + l4protocolNum + ", srcAddr=" + srcAddr + ", dstAddr=" + dstAddr + ", srcPort=" + srcPort + ", dstPort=" + dstPort + ", origBytes=" + origBytes + ", origPackets=" + origPackets + ", replyBytes=" + replyBytes + ", replyPackets=" + replyPackets + ", mark=" + mark + ", state=" + state + ", timeout=" + timeout + ", id=" + id + "]";
	}
}