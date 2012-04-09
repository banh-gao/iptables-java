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

import net.sf.jIPtables.log.LogListener;
import net.sf.jIPtables.log.LogTracker;
import net.sf.jIPtables.log.Packet;



public class Test {
	public static void main(String[] args) {
		
		LogTracker t = LogTracker.getInstance();
		
		t.addLogListener(new LogListener() {
			@Override
			public void onNewLog(Packet newPacket) {
				if("INDROPPED".equals(newPacket.getPrefix()))
					System.out.println("IF: "+ newPacket.getINInterface());
			}
		});
	}
}
