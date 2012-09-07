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
 * A TCP packet logged by the firewall
 */
public class TCPPacket extends IPv4Packet {

	private int sport;
	private int dport;
	private long seq;
	private long ackseq;
	private long window;
	private long checksum;
	private int urgp;
	private boolean urg;
	private boolean ack;
	private boolean psh;
	private boolean rst;
	private boolean syn;
	private boolean fin;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("spt".equals(field))
			sport = Integer.parseInt(value);
		else if ("dpt".equals(field))
			dport = Integer.parseInt(value);
		else if ("seq".equals(field))
			seq = Long.parseLong(value);
		else if ("ack".equals(field))
			ackseq = Long.parseLong(value);
		else if ("win".equals(field))
			window = Long.parseLong(value);
		else if ("tcp_sum".equals(field))
			checksum = Long.parseLong(value);
		else if ("urgF".equals(field))
			urg = true;
		else if ("urgp".equals(field))
			urgp = Integer.parseInt(value);
		else if ("ackF".equals(field))
			ack = true;
		else if ("pshF".equals(field))
			psh = true;
		else if ("rstF".equals(field))
			rst = true;
		else if ("synF".equals(field))
			syn = true;
		else if ("finF".equals(field))
			fin = true;
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
	 * @return The TCP sequence number
	 */
	public long getSequenceNumber() {
		return seq;
	}

	/**
	 * @return The TCP Acknowledgment number
	 */
	public long getAckSequenceNumber() {
		return ackseq;
	}

	/**
	 * @return The TCP window size in bytes
	 */
	public long getWindowSize() {
		return window;
	}

	/**
	 * @return The TCP urgent pointer
	 */
	public int getUrgentPointer() {
		return urgp;
	}
	
	/**
	 * @return The TCP checksum
	 */
	public long getChecksum() {
		return checksum;
	}

	/**
	 * @return True if the urg flag is set
	 */
	public boolean isUrg() {
		return urg;
	}

	/**
	 * @return True if the ack flag is set
	 */
	public boolean isAck() {
		return ack;
	}

	/**
	 * @return True if the psh flag is set
	 */
	public boolean isPsh() {
		return psh;
	}

	/**
	 * @return True if the rst flag is set
	 */
	public boolean isRst() {
		return rst;
	}

	/**
	 * @return True if the syn flag is set
	 */
	public boolean isSyn() {
		return syn;
	}

	/**
	 * @return True if the fin flag is set
	 */
	public boolean isFin() {
		return fin;
	}

	@Override
	public String toString() {
		return "TCPPacket [sport=" + sport + ", dport=" + dport + ", seq=" + seq + ", ackseq=" + ackseq + ", window=" + window + ", checksum=" + checksum + ", urgp=" + urgp + ", urg=" + urg + ", ack=" + ack + ", psh=" + psh + ", rst=" + rst + ", syn=" + syn + ", fin=" + fin + ", IPv4=" + super.toString() + "]";
	}
}
