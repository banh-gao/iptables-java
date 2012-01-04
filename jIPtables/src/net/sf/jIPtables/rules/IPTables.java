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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import net.sf.jIPtables.rules.RuleSet.TableType;

/**
 * Interact directly with the system iptables application. To execute correctly
 * make sure that the application has the correct unix permissions to access the
 * iptables commands
 * 
 */
public class IPTables {

	/**
	 * The command to execute iptables
	 */
	private final static String IPTABLES_COMMAND = "sudo /sbin/iptables";
	/**
	 * The command to execute for retrieve the system iptables configuration,
	 * the configuration will be read from the standard output
	 */
	private final static String SAVE_COMMAND = "sudo /sbin/iptables-save";
	/**
	 * The command to execute to save the system iptables configuration, the
	 * configuration will be written on the standard input
	 */
	private final static String RESTORE_COMMAND = "sudo /sbin/iptables-restore";

	/**
	 * @return The RuleSet that represent the current system configuration
	 * 
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 */
	public static RuleSet getCurrentRules() throws IOException {
		Process p = Runtime.getRuntime().exec(IPTables.SAVE_COMMAND + " -c");
		readError(p.getErrorStream());
		try {
			return RuleSet.parse(p.getInputStream());
		} catch (ParsingException e) {
			throw new IOException("Invalid iptables format. " + e.getParsingMessage());
		}
	}

	/**
	 * Apply the specified RuleSet to the system configuration
	 * 
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 * @throws NullPointerException
	 *             If the passed ruleset is null
	 */
	public static void setRules(RuleSet set) throws IOException {
		if (set == null)
			throw new NullPointerException();
		Process p = Runtime.getRuntime().exec(IPTables.RESTORE_COMMAND);
		OutputStream o = p.getOutputStream();
		o.write(set.getExportRules().getBytes());
		o.close();
		readError(p.getErrorStream());
	}

	/**
	 * Insert a rule at the specified position
	 * 
	 * @param rule
	 *            The rule to insert, the rule must be associated with a chain,
	 *            else an IllegalArgumentExceptin will be thrown
	 * @param ruleNum
	 *            The 1-indexed position where to insert
	 * @param table
	 *            The table where to insert the rule, if null the default table
	 *            is FILTER
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 * @throws IllegalArgumentException
	 *             If the rule is not associated with a chain
	 * @throws NullPointerException
	 *             If the passed rule is null
	 */
	public static void insertRule(Rule rule, int ruleNum, TableType table) throws IOException {
		if (rule == null)
			throw new NullPointerException();

		if (ruleNum < 1)
			throw new IllegalArgumentException("The rule number cannot be less than 1, " + ruleNum + " given");

		if (rule.getChainName().isEmpty())
			throw new IllegalArgumentException("Undefined chain for the passed rule");

		if (table == null)
			table = TableType.FILTER;

		String counter = "";
		if (rule.getPacketsNum() > 0 || rule.getBytesNum() > 0) {
			long packets = rule.getPacketsNum();
			rule.setPacketsNum(0);
			long bytes = rule.getBytesNum();
			rule.setBytesNum(0);
			counter = " -c " + packets + " " + bytes;
		}

		Process p = Runtime.getRuntime().exec(IPTables.IPTABLES_COMMAND + " -t " + table.getName() + " -I " + rule.getChainName() + " " + " " + ruleNum + rule.getCommand() + counter);
		readError(p.getErrorStream());
	}

	/**
	 * Replace a rule in the specified position
	 * 
	 * @param newRule
	 *            The replacement rule
	 * @param ruleNum
	 *            The 1-indexed position where the rule to replace is
	 * @param table
	 *            The table where the rule to replace is, if null the default
	 *            table is FILTER
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 * @throws IllegalArgumentException
	 *             If the rule is not associated with a chain
	 * @throws NullPointerException
	 *             If the passed rule is null
	 */
	public static void replaceRule(Rule newRule, int ruleNum, TableType table) throws IOException {
		if (newRule == null)
			throw new NullPointerException();
		if (ruleNum < 1)
			throw new IllegalArgumentException("The rule number cannot be less than 1, " + ruleNum + " given");

		if (newRule.getChainName().isEmpty())
			throw new IllegalArgumentException("Undefined chain for the passed rule");

		if (table == null)
			table = TableType.FILTER;

		String counter = "";
		if (newRule.getPacketsNum() > 0 || newRule.getBytesNum() > 0) {
			long packets = newRule.getPacketsNum();
			newRule.setPacketsNum(0);
			long bytes = newRule.getBytesNum();
			newRule.setBytesNum(0);
			counter = " -c " + packets + " " + bytes;
		}

		Process p = Runtime.getRuntime().exec(IPTables.IPTABLES_COMMAND + " -t " + table.getName() + " -R " + newRule.getChainName() + " " + ruleNum + " " + newRule.getCommand() + counter);
		readError(p.getErrorStream());
	}

	/**
	 * Append a rule at the end of the chain
	 * 
	 * @param rule
	 *            The rule to append
	 * @param table
	 *            The table where to append the rule, if null the default table
	 *            is FILTER
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 * @throws IllegalArgumentException
	 *             If the rule is not associated with a chain
	 * @throws NullPointerException
	 *             If the passed rule is null
	 */
	public static void appendRule(Rule rule, TableType table) throws IOException {
		if (rule == null)
			throw new NullPointerException();

		if (rule.getChainName().isEmpty())
			throw new IllegalArgumentException("Undefined chain for the passed rule");

		if (table == null)
			table = TableType.FILTER;

		String counter = "";
		if (rule.getPacketsNum() > 0 || rule.getBytesNum() > 0) {
			long packets = rule.getPacketsNum();
			rule.setPacketsNum(0);
			long bytes = rule.getBytesNum();
			rule.setBytesNum(0);
			counter = " -c " + packets + " " + bytes;
		}

		Process p = Runtime.getRuntime().exec(IPTables.IPTABLES_COMMAND + " -t " + table.getName() + " -A " + rule.getChainName() + " " + rule.getCommand() + counter);
		readError(p.getErrorStream());
	}

	/**
	 * Delete the specified rule
	 * 
	 * @param rule
	 *            The rule to delete
	 * @param table
	 *            The table where the rule to delete is, if null the default
	 *            table is FILTER
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 * @throws IllegalArgumentException
	 *             If the rule is not associated with a chain
	 * @throws NullPointerException
	 *             If the passed rule is null
	 */
	public static void deleteRule(Rule rule, TableType table) throws IOException {
		if (rule == null)
			throw new NullPointerException();

		if (rule.getChainName().isEmpty())
			throw new IllegalArgumentException("Undefined chain for the passed rule");

		if (table == null)
			table = TableType.FILTER;

		Process p = Runtime.getRuntime().exec(IPTables.IPTABLES_COMMAND + " -t " + table.getName() + " -D " + rule.getChainName() + " " + rule.getCommand());
		readError(p.getErrorStream());
	}

	/**
	 * Delete the rule at the specified position
	 * 
	 * @param ruleNum
	 *            The 1-indexed position where the rule to delete is
	 * @param chain
	 *            The chain where the rule to delete is
	 * @param table
	 *            The table where the rule to delete is, if null the default
	 *            table is FILTER
	 * @throws IOException
	 *             If the operation cannot be completed, for example for
	 *             insufficient privileges or unsupported iptables version
	 */
	public static void deleteRule(int ruleNum, String chain, TableType table) throws IOException {
		if (ruleNum < 1)
			throw new IllegalArgumentException("The rule number cannot be less than 1, " + ruleNum + " given");

		if (chain == null || chain.isEmpty())
			throw new IllegalArgumentException("Invalid chain name");

		if (table == null)
			table = TableType.FILTER;
		Process p = Runtime.getRuntime().exec(IPTables.IPTABLES_COMMAND + " -t " + table.getName() + " -D " + chain + " " + ruleNum);
		readError(p.getErrorStream());
	}

	/**
	 * Read from the errorstream of the executed command
	 * 
	 * @throws IOException
	 *             If there is an error in the stream
	 */
	private static void readError(InputStream errorStream) throws IOException {
		BufferedReader b = new BufferedReader(new InputStreamReader(errorStream));
		String error = "";
		for (String line = b.readLine(); line != null; line = b.readLine())
			error += line;
		if (error.length() > 0)
			throw new IOException(error);
	}
}
