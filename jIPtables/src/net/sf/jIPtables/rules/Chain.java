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

package net.sf.jIPtables.rules;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An iptables chain that contains the corresponding rules
 * 
 */
public class Chain extends Command implements Iterable<Rule>, Cloneable {

	private static final Pattern chainPattern = Pattern.compile(":[\\s]*([^ ]*)[\\s]*([^ ]*)[\\s]*\\[(\\d*):(\\d*)\\]");

	/**
	 * The chain name
	 */
	private final String name;
	/**
	 * The number of packets
	 */
	private long packets;
	/**
	 * The number of bytes
	 */
	private long bytes;

	/**
	 * The default policy
	 */
	private Policy defaultPolicy = Policy.ACCEPT;

	/**
	 * The default policy of the chain, only built-in chains supports the
	 * default
	 * policy
	 * 
	 */
	public enum Policy {
		ACCEPT, DROP, REJECT
	};

	private final List<Rule> rules = new LinkedList<Rule>();

	/**
	 * Create a chain with the specified name
	 * 
	 * @throws IllegalArgumentException
	 *             If the passed name is null or is empty
	 */
	public Chain(String name) {
		if (name == null)
			throw new IllegalArgumentException("Invalid chain name");
		this.name = name;
	}

	/**
	 * Try to parse an iptables chain definition
	 * 
	 * @throws ParsingException
	 *             If some parsing error occurs
	 * @throws NullPointerException
	 *             If the passed chain is null
	 */
	protected static Chain parse(String chain) throws ParsingException {
		if (chain == null)
			throw new NullPointerException();

		Matcher m = Chain.chainPattern.matcher(chain);
		m.find();
		Chain c;

		if (m.groupCount() != 4)
			throw new ParsingException("Invalid chain format");

		c = new Chain(m.group(1));
		if ("ACCEPT".equalsIgnoreCase(m.group(2)))
			c.setDefaultPolicy(Policy.ACCEPT);
		else if ("DROP".equalsIgnoreCase(m.group(2)))
			c.setDefaultPolicy(Policy.DROP);

		if (m.groupCount() == 4) {
			c.setPacketsNum(Long.parseLong(m.group(3)));
			c.setBytesNum(Long.parseLong(m.group(4)));
		}
		return c;
	}

	@Override
	public String getCommand() {
		StringBuilder out = new StringBuilder(":" + name + " " + defaultPolicy);
		if (packets > -1 && bytes > -1)
			out.append(" [" + packets + ":" + bytes + "]\n");
		for (Rule r : rules) {
			if (r.getPacketsNum() > 0 && r.getBytesNum() > 0)
				out.append("[" + r.getPacketsNum() + ":" + r.getBytesNum() + "] ");

			out.append("-A " + name + r.getCommand() + "\n");
		}
		out.delete(out.length() - 1, out.length());
		return out.toString();
	}

	/**
	 * Add the specified rule to the chain, the rules are applied in the order
	 * they are inserted
	 * 
	 * @throws NullPointerException
	 *             If the passed rule is null
	 */
	public void addRule(Rule rule) {
		if (rule == null)
			throw new NullPointerException();
		rules.add(rule);
		rule.chainName = name;
		rule.ruleNumber = rules.size();
	}

	/**
	 * @return A list of the rules in this chain, the list is sorted in the
	 *         order of insertion
	 */
	public List<Rule> getRules() {
		return Collections.unmodifiableList(rules);
	}

	/**
	 * Set the number of packets that matches this chain
	 * 
	 * @throws IllegalArgumentException
	 *             If the passed number of packets is lesser of 0
	 */
	public void setPacketsNum(long packets) {
		if (packets < 0)
			throw new IllegalArgumentException("The packets number cannot be less than 0, " + packets + " given");
		this.packets = packets;
	}

	/**
	 * Set the number of bytes that matches this chain
	 * 
	 * @throws IllegalArgumentException
	 *             If the passed number of bytes is lesser of 0
	 */
	public void setBytesNum(long bytes) {
		if (bytes < 0)
			throw new IllegalArgumentException("The bytes number cannot be less than 0, " + bytes + " given");
		this.bytes = bytes;
	}

	/**
	 * @return The chain name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return The number of packets that matches this chain
	 */
	public long getPacketsNum() {
		return packets;
	}

	/**
	 * @return The number of bytes that matches this chain
	 */
	public long getBytesNum() {
		return bytes;
	}

	/**
	 * Set the default policy of the chain
	 * 
	 * @param defaultPolicy
	 *            The default policy
	 * @throws NullPointerException
	 *             If the passed policy is null
	 */
	public void setDefaultPolicy(Policy defaultPolicy) {
		if (defaultPolicy == null)
			throw new NullPointerException();
		this.defaultPolicy = defaultPolicy;
	}

	/**
	 * @return The default policy of the chain
	 */
	public Policy getDefaultPolicy() {
		return defaultPolicy;
	}

	@Override
	public Chain clone() {
		try {
			Chain c = parse(getCommand());
			for (Rule r : rules)
				c.addRule(r.clone());
			return c;
		} catch (ParsingException e) {
			// This should never happen
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder("Chain " + name + " (policy " + defaultPolicy + " " + packets + " packets, " + bytes + " bytes)\n");
		for (Rule r : rules)
			out.append(r.toString() + "\n");
		return out.toString();
	}

	@Override
	public Iterator<Rule> iterator() {
		return rules.iterator();
	}
}
