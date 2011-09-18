/*
 * Created on 20-mag-03
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

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

import javax.activation.MimeType;


/**
 * @author reto
 */
public class MediaRange implements Comparable<MediaRange> {

	private String type, subtype;
	// accessed by AccedHeaderEntry
	Map<String, String> parameters = new HashMap<String, String>();

	/**
	 * @param pattern 
	 * @throws InvalidPatternException 
	 * 
	 */
	public MediaRange(String pattern) throws InvalidPatternException {
		try {
			StringTokenizer subtypeParamTokens;

			if (pattern.indexOf('/') > -1) {
				StringTokenizer tokens = new StringTokenizer(pattern, "/");
				type = tokens.nextToken();
				String subtypeAnParams;
				subtypeAnParams = tokens.nextToken();
				subtypeParamTokens = new StringTokenizer(subtypeAnParams, ";");
				subtype = subtypeParamTokens.nextToken();
			} else {
				if (pattern.charAt(0) != '*') {
					throw new InvalidPatternException("Invalid pattern "
							+ pattern + ": ");
				}
				type = "*";
				subtype = "*";
				subtypeParamTokens = new StringTokenizer(pattern, ";");
				subtypeParamTokens.nextToken(); // read the "*"

			}

			while (subtypeParamTokens.hasMoreTokens()) {
				String parameterToken = subtypeParamTokens.nextToken();
				StringTokenizer nameValueSplitter = new StringTokenizer(
						parameterToken, "=");
				String name = nameValueSplitter.nextToken().trim();
				String value = nameValueSplitter.nextToken().trim();
				parameters.put(name, value);
			}
		} catch (Exception e) {
			throw new InvalidPatternException("Invalid pattern " + pattern
					+ ": ");
		}
	}

	/**
	 * @param mimeType
	 * @return true if the specified mimeType matches this MediaRange
	 */
	public boolean match(MimeType mimeType) {
		if (match(type, mimeType.getPrimaryType())
				&& match(subtype, mimeType.getSubType())) {
			Iterator<String> parameterIter = parameters.keySet().iterator();
			while (parameterIter.hasNext()) {
				String currentName = parameterIter.next();
				String typeParameterValue = mimeType.getParameter(currentName);
				if (typeParameterValue == null) {
					return false;
				}
				if (!typeParameterValue.equals(parameters.get(currentName))) {
					return false;
				}
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param subtype
	 * @param string
	 * @return
	 */
	private boolean match(String pattern, String string) {
		boolean result = pattern.equals("*") || pattern.equals(string);
		return result;
	}

	public String toString() {
		StringWriter resultWriter = new StringWriter();
		resultWriter.write(type);
		resultWriter.write('/');
		resultWriter.write(subtype);
		Iterator<String> parameterIter = parameters.keySet().iterator();
		while (parameterIter.hasNext()) {
			String currentName = parameterIter.next();
			String currentValue = parameters.get(currentName);
			resultWriter.write("; ");
			resultWriter.write(currentName);
			resultWriter.write(currentValue);
		}
		return resultWriter.toString();
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object arg0) {
		if (arg0 instanceof MediaRange) {
			return ((MediaRange) arg0).type.equals(type)
					&& ((MediaRange) arg0).subtype.equals(subtype);
		}
		return false;
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return type.hashCode() & subtype.hashCode();
	}

	/**
	 * @return the number of '*' in the range (0,1 or 2)
	 */
	public int getAsterixCount() {
		if (subtype.equals("*")) {
			return 2;
		}
		if (type.equals("*")) {
			return 1;
		}
		return 0;
	}

	public int compareTo(MediaRange other) {
		if (equals(other)) {
			return 0;
		}
		if (getAsterixCount() > other.getAsterixCount()) {
			return 1;
		}
		if (getAsterixCount() < other.getAsterixCount()) {
			return -1;
		}
		return toString().compareTo(other.toString());
	}
}