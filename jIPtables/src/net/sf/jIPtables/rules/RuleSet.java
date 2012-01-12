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

package net.sf.jIPtables.rules;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Iterator;

/**
 * Contains the configuration tables used by iptables
 * 
 */
public class RuleSet implements Iterable<Table> {

	private final Table filterTable;
	private final Table natTable;
	private final Table mangleTable;
	private final Table rawTable;

	/**
	 * The supported tables
	 */
	public enum TableType {
		FILTER, NAT, MANGLE, RAW;

		/**
		 * @return The table type as string
		 */
		public String getName() {
			switch (this) {
				case FILTER :
					return "filter";
				case NAT :
					return "nat";
				case MANGLE :
					return "mangle";
				case RAW :
					return "raw";
			}
			return "";
		};

		/**
		 * Get the table type from string
		 * 
		 * @return The corresponding table type or null if no type corresponds
		 */
		public static TableType getType(String table) {
			if ("filter".equalsIgnoreCase(table))
				return FILTER;
			else if ("nat".equalsIgnoreCase(table))
				return NAT;
			else if ("mangle".equalsIgnoreCase(table))
				return MANGLE;
			else if ("raw".equalsIgnoreCase(table))
				return RAW;
			else
				return null;
		}
	};

	/**
	 * Create an empty RuleSet
	 */
	public RuleSet() {
		filterTable = new Table("filter");
		natTable = new Table("nat");
		mangleTable = new Table("mangle");
		rawTable = new Table("raw");
	}

	/**
	 * Try to parse the input stream as iptables rules
	 * 
	 * @return The parsed RuleSet
	 * @throws ParsingException
	 *             If some parsing error occurs
	 * @throws IOException
	 *             If some I/O error occurs in reading the input stream
	 * @throws NullPointerException
	 *             If the passed stream is null
	 */
	public static RuleSet parse(InputStream ruleStream) throws ParsingException, IOException {
		if (ruleStream == null)
			throw new NullPointerException();
		BufferedReader b = new BufferedReader(new InputStreamReader(ruleStream));
		StringBuilder s = new StringBuilder();
		for (String line = b.readLine(); line != null; line = b.readLine())
			s.append(line + "\n");
		return RuleSet.parse(s.toString());
	}

	/**
	 * Try to parse the input as iptables rules
	 * 
	 * @return The parsed RuleSet
	 * @throws ParsingException
	 *             If the operation cannot be completed, for example for
	 *             insufficient unix privileges
	 * @throws NullPointerException
	 *             If the passed rules is null
	 */
	public static RuleSet parse(String rules) throws ParsingException {
		if (rules == null)
			throw new NullPointerException();

		RuleSet parsedRules = new RuleSet();
		BufferedReader r = new BufferedReader(new StringReader(rules));
		Table currentTable = parsedRules.filterTable;

		int lineNum = 1;
		String line;
		try {
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (isTableLine(line))
					currentTable = getCurrentTable(parsedRules, line);
				else if (!isCommentLine(line))
					parseLine(line, currentTable);
				lineNum++;
			}
		} catch (ParsingException e) {
			throw new ParsingException(lineNum, e.getParsingMessage());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return parsedRules;

	}

	private static boolean isCommentLine(String line) {
		return line.charAt(0) == '#';
	}

	private static boolean isTableLine(String line) {
		return line.charAt(0) == '*';
	}

	private static Table getCurrentTable(RuleSet ruleSet, String tableLine) throws ParsingException {
		if ("filter".equals(tableLine.substring(1)))
			return ruleSet.filterTable;
		else if ("nat".equals(tableLine.substring(1)))
			return ruleSet.natTable;
		else if ("mangle".equals(tableLine.substring(1)))
			return ruleSet.mangleTable;
		else if ("raw".equals(tableLine.substring(1)))
			return ruleSet.rawTable;
		else
			throw new ParsingException("Invalid table name " + tableLine.substring(1));
	}

	/**
	 * @return The table corresponding to the specified table type or null if no
	 *         table matches
	 */
	public Table getTable(TableType type) {
		switch (type) {
			case FILTER :
				return filterTable;
			case MANGLE :
				return mangleTable;
			case NAT :
				return natTable;
			case RAW :
				return rawTable;
		}
		return null;
	}

	/**
	 * @return The available tables
	 */
	public Table[] getTables() {
		Table[] t = new Table[4];
		t[0] = filterTable;
		t[1] = mangleTable;
		t[2] = natTable;
		t[3] = rawTable;
		return t;
	}

	@Override
	public Iterator<Table> iterator() {
		return Arrays.asList(getTables()).iterator();
	}

	/**
	 * @return The rules in iptables format
	 */
	public String getExportRules() {
		return filterTable.getCommand() + natTable.getCommand() + mangleTable.getCommand() + rawTable.getCommand() + "COMMIT\n";
	}

	/**
	 * Parse a generic command line
	 */
	private static void parseLine(String rule, Table table) throws ParsingException {
		if (rule.charAt(0) == ':')
			parseChain(rule, table);
		else
			parseCommand(rule, table);
	}

	/**
	 * Parse a chain command
	 */
	private static void parseChain(String chain, Table table) throws ParsingException {
		table.addChain(Chain.parse(chain));
	}

	/**
	 * Parse a generic command (not chain)
	 */
	private static void parseCommand(String rule, Table table) throws ParsingException {

		if (!rule.startsWith("-A") && rule.charAt(0) != '[')
			return;

		Rule r = Rule.buildFromCommand(rule);
		if (r == null)
			return;
		String chainName = r.getChainName();
		Chain c = table.getChain(chainName);
		if (c == null)
			throw new ParsingException("Undefined chain " + chainName);

		c.addRule(r);
	}

	@Override
	public String toString() {
		return filterTable.toString() + "\n" + natTable.toString() + "\n" + mangleTable.toString();
	}
}