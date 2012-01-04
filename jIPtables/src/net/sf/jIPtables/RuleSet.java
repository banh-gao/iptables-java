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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;

/**
 * Contains the configuration tables used by iptables
 * 
 */
public class RuleSet {

	private Table filterTable;
	private Table natTable;
	private Table mangleTable;
	private Table rawTable;

	/**
	 * The supported tables
	 */
	public enum TableType {
		FILTER, NAT, MANGLE, RAW;
		/**
		 * Get the table name
		 */
		public String getName() {
			switch (this) {
			case FILTER:
				return "filter";
			case NAT:
				return "nat";
			case MANGLE:
				return "mangle";
			case RAW:
				return "raw";
			}
			return "";
		};

		public static TableType getType(String table) {
			if ("filter".equals(table))
				return FILTER;
			else if ("nat".equals(table))
				return NAT;
			else if ("mangle".equals(table))
				return MANGLE;
			else if ("raw".equals(table))
				return RAW;
			else
				throw new IllegalArgumentException("Invalid table name");
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
	 * Try to parse the input as iptables rules
	 * 
	 * @return The parsed RuleSet
	 * @throws ParsingException
	 *             If some parsing error occurs
	 * @throws IOException
	 *             If some I/O error occurs in reading the input stream
	 */
	public static RuleSet parse(InputStream ruleStream)
			throws ParsingException, IOException {
		if (ruleStream == null)
			throw new NullPointerException();
		BufferedReader b = new BufferedReader(new InputStreamReader(ruleStream));
		StringBuilder s = new StringBuilder();
		for (String line = b.readLine(); line != null; line = b.readLine()) {
			s.append(line + "\n");
		}
		return RuleSet.parse(s.toString());
	}

	/**
	 * Try to parse the input as iptables rules
	 * 
	 * @return The parsed RuleSet
	 * @throws ParsingException
	 *             If the operation cannot be completed, for example for
	 *             insufficient unix privileges
	 */
	public static RuleSet parse(String rules) throws ParsingException {
		if(rules == null)
			throw new NullPointerException();
		RuleSet parsedRules = new RuleSet();
		BufferedReader r = new BufferedReader(new StringReader(rules));
		try {
			Table currentTable = parsedRules.filterTable;
			int lineNum = 1;
			for (String line = r.readLine(); line != null; line = r.readLine(), lineNum++) {
				line = line.trim();
				if (line.charAt(0) == '#') {
					continue;
				} else if (line.charAt(0) == '*') {
					if ("filter".equals(line.substring(1))) {
						currentTable = parsedRules.filterTable;
						continue;
					} else if ("nat".equals(line.substring(1))) {
						currentTable = parsedRules.natTable;
						continue;
					} else if ("mangle".equals(line.substring(1))) {
						currentTable = parsedRules.mangleTable;
						continue;
					} else if ("raw".equals(line.substring(1))) {
						currentTable = parsedRules.rawTable;
						continue;
					} else {
						throw new ParsingException(lineNum,
								"Invalid table name " + line.substring(1));
					}
				} else {
					try {
						parseLine(line, currentTable);
					} catch (ParsingException e) {
						throw new ParsingException(lineNum,
								e.getParsingMessage());
					}
				}
			}
			return parsedRules;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Get the specified table
	 */
	public Table getTable(TableType type) {
		switch (type) {
		case FILTER:
			return filterTable;
		case MANGLE:
			return mangleTable;
		case NAT:
			return natTable;
		case RAW:
			return rawTable;
		}
		return null;
	}

	public Table[] getTables() {
		Table[] t = new Table[4];
		t[0] = filterTable;
		t[1] = mangleTable;
		t[2] = natTable;
		t[3] = rawTable;
		return t;
	}

	/**
	 * Get the rules in iptables format
	 */
	public String getExportRules() {
		return filterTable.getCommand() + natTable.getCommand()
				+ mangleTable.getCommand() + rawTable.getCommand() + "COMMIT\n";
	}

	/**
	 * Parse a generic command line
	 */
	private static void parseLine(String rule, Table table)
			throws ParsingException {
		if (rule.charAt(0) == ':')
			parseChain(rule, table);
		else
			parseCommand(rule, table);
	}

	/**
	 * Parse a chain command
	 */
	private static void parseChain(String chain, Table table)
			throws ParsingException {
		table.addChain(Chain.parse(chain));
	}

	/**
	 * Parse a generic command (not chain)
	 */
	private static void parseCommand(String rule, Table table)
			throws ParsingException {

		if (!rule.startsWith("-A") && rule.charAt(0) != '[') {
			return;
		}

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
		return filterTable.toString() + "\n" + natTable.toString() + "\n"
				+ mangleTable.toString();
	}
}