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
 * An IPv4 packet logged by the firewall
 */
public abstract class IPv4Packet extends Packet {

	private int totalLength;

	private int tos;
	private int ttl;
	private int id;
	private int transportProtocol;

	private boolean reservedFragment;
	private boolean dontFragment;
	private boolean moreFragments;
	private int fragmentOffset;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);

		if ("tos".equals(field))
			tos = Integer.parseInt(value);
		else if ("ttl".equals(field))
			ttl = Integer.parseInt(value);
		else if ("transport_proto".equals(field))
			transportProtocol = Integer.parseInt(value);
		else if ("tot_len".equals(field))
			totalLength = Integer.parseInt(value);
		else if ("id".equals(field))
			id = Integer.parseInt(value);
		else if ("rf".equals(field))
			reservedFragment = true;
		else if ("df".equals(field))
			dontFragment = true;
		else if ("mf".equals(field))
			moreFragments = true;
		else if ("frag".equals(field))
			fragmentOffset = Integer.parseInt(value);
	}

	/**
	 * @return The fragment offset of an ip fragment packet
	 */
	public int getFragmentOffset() {
		return fragmentOffset;
	}

	/**
	 * @return The IP packet identification id used by the ip fragments
	 */
	public int getPacketId() {
		return id;
	}

	/**
	 * @return The IP Type Of Service field value
	 */
	public int getTos() {
		return tos;
	}

	/**
	 * @return The total length of the ip header and the payload in bytes
	 */
	public int getTotalLength() {
		return totalLength;
	}

	/**
	 * @return The TimeToLive
	 */
	public int getTTL() {
		return ttl;
	}

	/**
	 * @return True if the ip don't fragment flag is set
	 */
	public boolean isDontFragment() {
		return dontFragment;
	}

	/**
	 * @return True if the ip more fragments flag is set
	 */
	public boolean isMoreFragments() {
		return moreFragments;
	}

	/**
	 * @return True if the ip reserved fragment flag is set
	 */
	public boolean isReservedFragment() {
		return reservedFragment;
	}

	public int getTransportProtocolId() {
		return transportProtocol;
	}

	@Override
	public String toString() {
		return "IPv4Packet [totalLength=" + totalLength + ", tos=" + tos + ", ttl=" + ttl + ", id=" + id + ", transportProtocol=" + transportProtocol + ", reservedFragment=" + reservedFragment + ", dontFragment=" + dontFragment + ", moreFragments=" + moreFragments + ", fragmentOffset=" + fragmentOffset + ", toString()=" + super.toString() + "]";
	}
}
