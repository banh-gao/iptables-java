/**
 * @package		jIPtables
 * @copyright	Copyright (C) 2011 IPTables Java LIbrary. All rights reserved.
 * @license		GNU/GPL, see COPYING file
 * @author		Daniel Zozin
 *
 * This file is part of IPTables Java LIbrary.
 * IPTables Java LIbrary is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * IPTables Java LIbrary is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IPTables Java LIbrary.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package net.sf.jIPtables;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.sf.jIPtables.connection.Connection;

/**
 * A rule for the firewall. You can specify the generic rule options, a protocol
 * matcher(-p option), a target (-j option) and additional matcher(-m option)
 * 
 */
public class Rule extends Command implements Cloneable {

	private static final Pattern counterPatten = Pattern
			.compile("\\[(\\d*):(\\d*)\\]");

	// FIXME: Accept arguments with escaped double quotes
	private static final Pattern argumentPattern = Pattern
			.compile("(!?)[\\s]*([-]{1,2}[-a-zA-Z0-9]*)([\\s|\"]*)([\\w|.|?|=|&|+|\\s|:|,|\\\\|/]*)([\\s|\"]|$)");

	/**
	 * The chainName field can be written only by the rule itself and by other
	 * classes in the same package
	 */
	protected String chainName = "";
	/**
	 * The rule number inside a chain
	 */
	protected int ruleNumber = 1;
	/**
	 * The number of packets
	 */
	private long packets;
	/**
	 * The number of bytes
	 */
	private long bytes;

	/**
	 * Create an empty rule
	 */
	public Rule() {
	}

	/**
	 * Created a rule associated to the specified chain
	 */
	public Rule(String chainName) {
		if (chainName == null)
			this.chainName = "";
		else
			this.chainName = chainName;
	}

	/**
	 * Initialize a rule using the passed command arguments
	 */
	public static Rule buildFromCommand(String ruleCommand) {
		Matcher cm = counterPatten.matcher(ruleCommand);

		Rule rule = new Rule();

		// Search for counters
		if (cm.find()) {
			rule.setPacketsNum(Long.parseLong(cm.group(1)));
			rule.setBytesNum(Long.parseLong(cm.group(2)));
			// Remove counters from command
			ruleCommand = ruleCommand.substring(cm.group(0).length());
		}

		rule.initRule(rule, ruleCommand);

		return rule;
	}

	/**
	 * Initialize the passed rule with the string command
	 */
	private void initRule(Rule rule, String ruleCommand) {
		Matcher m = argumentPattern.matcher(ruleCommand);

		while (m.find()) {
			if (m.groupCount() == 5) {
				boolean isNegated = (m.group(1) != null && !m.group(1)
						.isEmpty());

				String optionName = m.group(2).trim();
				String value = m.group(4).trim();

				// Set the chain name and don't store as an option
				if ("-A".equals(optionName) || "--append".equals(optionName)) {
					chainName = value;
					continue;
				}

				rule.setOption(optionName, value);
				rule.setNegated(optionName, isNegated);
			}
		}
	}

	/**
	 * Get the name of the associated chain
	 */
	public String getChainName() {
		return chainName;
	}

	/**
	 * Get the 1-indexed number of the rule inside a chain, if the rule is not
	 * associated with a chain an IllegalStateException will be throwed
	 */
	public int getRuleNumber() {
		if (chainName.isEmpty())
			throw new IllegalStateException(
					"Invalid rule number, the rule is not associated with a chain");
		return ruleNumber;
	}

	/**
	 * Set the number of packets that have matched this rule
	 * 
	 */
	public void setPacketsNum(long packets) {
		if (packets < 0)
			throw new IllegalArgumentException(
					"The packets number cannot be less than 0, " + packets
							+ " given");
		this.packets = packets;
	}

	/**
	 * Set the number of bytes that have matched this rule
	 * 
	 */
	public void setBytesNum(long bytes) {
		if (bytes < 0)
			throw new IllegalArgumentException(
					"The bytes number cannot be less than 0, " + bytes
							+ " given");
		this.bytes = bytes;
	}

	/**
	 * Set the number of packets that have matched this rule
	 */
	public long getPacketsNum() {
		return packets;
	}

	/**
	 * Get the number of bytes that have matched this rule
	 */
	public long getBytesNum() {
		return bytes;
	}

	/**
	 * Get a copy of this rule
	 */
	@Override
	public Rule clone() {
		return buildFromCommand(getCommand());
	}

	@Override
	public String toString() {
		return "Rule " + super.toString();
	}
}
