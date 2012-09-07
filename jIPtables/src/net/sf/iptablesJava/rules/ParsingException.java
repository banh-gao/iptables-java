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

package net.sf.iptablesJava.rules;

/**
 * Exception throwed when an error occurs in rule parsing
 * 
 */
public class ParsingException extends Exception {

	private int line;
	private String parsingMessage;

	/**
	 * Create an exception using only the line number where the parsing error
	 * occurs
	 */
	ParsingException(int line) {
		super("Parsing error at line " + line);
	}

	/**
	 * Create an exception using only a message to describe the error
	 */
	ParsingException(String message) {
		super("Parsing error: " + message);
		parsingMessage = message;
	}

	/**
	 * Create an exception using the line number where the parsing error occurs
	 * and an error description message
	 */
	ParsingException(int line, String message) {
		super("Parsing error at line " + line + ": " + message);
		this.line = line;
		parsingMessage = message;
	}

	/**
	 * Get the line where the parsing error occurs
	 */
	public int getLine() {
		return line;
	}

	/**
	 * Get the parsing error message
	 */
	public String getParsingMessage() {
		return parsingMessage;
	}
}