/*
 * Created on May 15, 2004
 * 
 * 
 * ====================================================================
 * 
 * The WYMIWYG Software License, Version 1.0
 * 
 * Copyright (c) 2002-2003 WYMIWYG All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * 3. The end-user documentation included with the redistribution, if any, must
 * include the following acknowlegement: "This product includes software
 * developed by WYMIWYG." Alternately, this acknowlegement may appear in the
 * software itself, if and wherever such third-party acknowlegements normally
 * appear.
 * 
 * 4. The name "WYMIWYG" or "WYMIWYG.org" must not be used to endorse or promote
 * products derived from this software without prior written permission. For
 * written permission, please contact wymiwyg@wymiwyg.org.
 * 
 * 5. Products derived from this software may not be called "WYMIWYG" nor may
 * "WYMIWYG" appear in their names without prior written permission of WYMIWYG.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL WYMIWYG OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by many individuals on
 * behalf of WYMIWYG. For more information on WYMIWYG, please see
 * http://www.WYMIWYG.org/.
 * 
 * This licensed is based on The Apache Software License, Version 1.1, see
 * http://www.apache.org/.
 */
package org.wymiwyg.wrhapi.util;


/**
 * @author reto
 */
public class AcceptHeaderEntry implements Comparable<AcceptHeaderEntry> {
	MediaRange range;
	float q;
	/**
	 * @param range
	 * @param q
	 */
	public AcceptHeaderEntry(MediaRange range, float q) {
		this.range = range;
		this.q = q;
	}
	/**
	 * @param string 
	 * @throws InvalidPatternException 
	 */
	public AcceptHeaderEntry(String string) throws InvalidPatternException {
		if ("*".equals(string)) { // I think this is illegal but some clients like Java/1.4.2_03 on OS X do
			string = "*/*";
		}
		range = new MediaRange(string);
		String qString = (String) range.parameters.remove("q");
		if (qString == null) {
			q = 1;
		} else {
			try {
				q = Float.parseFloat(qString);
			} catch (NumberFormatException ex) {
				throw new InvalidPatternException("could not parse "+qString+" as number in"+string);
			}
		}
	}
	
	/**
	 * @return Returns the q.
	 */
	public float getQ() {
		return q;
	}
	/**
	 * @return Returns the range.
	 */
	public MediaRange getRange() {
		return range;
	}

	public int compareTo(AcceptHeaderEntry other) {
		if (q > other.q) {
			return -1;
		}
		if (q < other.q) {
			return 1;
		}
		return range.compareTo(other.range);
	}

	public boolean equals(Object other) {
		if (other.getClass().equals(AcceptHeaderEntry.class)) {
			return (q == ((AcceptHeaderEntry) other).q)
					&& (range == ((AcceptHeaderEntry) other).range);
		} else {
			return false;
		}
	}
	
	public int hashCode() {
		return range.hashCode();
	}
	
	public String toString() {
		StringBuffer buffer = new StringBuffer(range.toString());
		buffer.append("; q=");
		buffer.append(q);
		return buffer.toString();
	}
}