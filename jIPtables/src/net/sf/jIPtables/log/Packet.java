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

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A packet logged by the firewall
 */
public class Packet {

	private Date date;

	private NetworkInterface inInterface;
	private NetworkInterface outInterface;

	private String srcMAC = "";
	private String dstMAC = "";

	private InetAddress srcIP;
	private InetAddress dstIP;

	private long mark;

	private long hook;

	private String protocol;

	private String prefix;

	protected int nfGroup;

	protected Packet() {
	}

	/**
	 * Return a packet implementation related to the specified protocol
	 */
	static Packet getPacket(String ipProtocol) {
		if ("tcp".equals(ipProtocol))
			return new TCPPacket();
		else if ("udp".equals(ipProtocol))
			return new UDPPacket();
		else if ("icmp".equals(ipProtocol))
			return new ICMPPacket();
		else if ("icmpv6".equals(ipProtocol))
			return new ICMPv6Packet();
		else if ("sctp".equals(ipProtocol))
			return new SCTPPacket();
		else if ("arp".equals(ipProtocol))
			return new ARPPacket();
		else if ("ipv4".equals(ipProtocol))
			return new IPv4Packet();
		else if ("ipv6".equals(ipProtocol))
			return new IPv6Packet();
		else
			return new Packet();
	}

	protected void setField(String field, String value) {
		if ("proto".equals(field))
			protocol = value;
		else if ("hook".equals(field))
			hook = Long.parseLong(value);
		else if ("mark".equals(field))
			mark = Long.parseLong(value);
		else if ("prefix".equals(field))
			prefix = value;
		else if ("src".equals(field))
			srcIP = parseAddress(value);
		else if ("dst".equals(field))
			dstIP = parseAddress(value);
		else if ("inDev".equals(field))
			inInterface = parseInterface(value);
		else if ("outDev".equals(field))
			outInterface = parseInterface(value);
		else if ("sec".equals(field))
			date = new Date(Long.parseLong(value));
	}

	/**
	 * @return A string of the passed name, it uses the format name=string
	 */
	protected static String getValue(String rawData, String name) {
		Pattern p = Pattern.compile(Pattern.quote(name) + "=([^ ]*)");
		Matcher m = p.matcher(rawData);
		if (m.find())
			return m.group(1);
		else
			return "";
	}

	/**
	 * @return An integer number of the passed name, it uses the format
	 *         name=number
	 */
	protected static int getIntValue(String rawData, String name) {
		Pattern p = Pattern.compile(Pattern.quote(name) + "=([0-9]*)");
		Matcher m = p.matcher(rawData);
		if (m.find())
			try {
				return Integer.parseInt(m.group(1));
			} catch (NumberFormatException e) {
				e.printStackTrace();
				return 0;
			}
		else
			return 0;
	}

	/**
	 * @return A long number of the passed name, it uses the format name=number
	 */
	protected static long getLongValue(String rawData, String name) {
		Pattern p = Pattern.compile(Pattern.quote(name) + "=([0-9]*)");
		Matcher m = p.matcher(rawData);
		if (m.find())
			return Long.parseLong(m.group(1));
		else
			return 0;
	}

	/**
	 * @return True if the specified flag is set
	 */
	protected static boolean isFlagSet(String rawData, String flag) {
		return rawData.matches(".*" + flag + ".*");
	}

	/**
	 * @return The network interface from name
	 */
	protected static NetworkInterface parseInterface(String ifName) {
		try {
			NetworkInterface netif = NetworkInterface.getByName(ifName);
			return netif;
		} catch (SocketException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * @return The parsed ip address
	 */
	protected static InetAddress parseAddress(String addr) {
		try {
			return InetAddress.getByName(addr);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * @return The log prefix assigned by nflog
	 */
	public String getPrefix() {
		return prefix;
	}

	/**
	 * @return The level 4 protocol name, for example TCP or ICMP
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * @return The source mac address of the fragment
	 */
	public String getSourceMac() {
		return srcMAC;
	}

	/**
	 * @return The destination mac address of the fragment
	 */
	public String getDestinationMac() {
		return dstMAC;
	}

	/**
	 * @return The source ip address
	 */
	public InetAddress getSourceAddress() {
		return srcIP;
	}

	/**
	 * @return The destination ip address
	 */
	public InetAddress getDestinationAddress() {
		return dstIP;
	}

	/**
	 * @return The date of the moment when the packet was captured
	 */
	public Date getDate() {
		return new Date(date.getTime());
	}

	/**
	 * @return The incoming interface of the packet
	 */
	public NetworkInterface getINInterface() {
		return inInterface;
	}

	/**
	 * @return The outgoing interface of the packet
	 */
	public NetworkInterface getOUTInterface() {
		return outInterface;
	}

	/**
	 * @return The mark of this packet applied from iptables using MARK target
	 */
	public long getMark() {
		return mark;
	}

	/**
	 * @return The netfilter hook
	 */
	public long getHook() {
		return hook;
	}

	/**
	 * @return The netfilter group
	 */
	public int getNFGroup() {
		return nfGroup;
	}

	@Override
	public String toString() {
		return "Packet [date=" + date + ", inInterface=" + inInterface + ", outInterface=" + outInterface + ", srcMAC=" + srcMAC + ", dstMAC=" + dstMAC + ", srcIP=" + srcIP + ", dstIP=" + dstIP + ", mark=" + mark + ", hook=" + hook + ", protocol=" + protocol + ", prefix=" + prefix + ", nfGroup=" + nfGroup + "]";
	}
}
