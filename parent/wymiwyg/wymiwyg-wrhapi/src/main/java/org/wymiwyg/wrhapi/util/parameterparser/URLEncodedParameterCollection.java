/*
 * Copyright  2002-2006 WYMIWYG (http://wymiwyg.org)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.wymiwyg.wrhapi.util.parameterparser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.channels.Channels;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.wymiwyg.wrhapi.MessageBody;

/**
 * @author reto
 * 
 */
public class URLEncodedParameterCollection extends AbstractParameterCollection {

	private String encodedCollection;

	/**
	 * creates a parameter-collection parsing the specified message-body
	 * 
	 * @param messageBody
	 *            the messageBody to parse
	 */
	public URLEncodedParameterCollection(MessageBody messageBody) {
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		try {
			messageBody.writeTo(Channels.newChannel(byteOut));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		encodedCollection = new String(byteOut.toByteArray());
	}

	/**
	 * creates a parameter-collection parsing the specified string
	 * 
	 * @param encodedCollection
	 *            the string to parse
	 */
	public URLEncodedParameterCollection(String encodedCollection) {
		this.encodedCollection = encodedCollection;
	}

	@Override
	public Iterator<KeyValuePair<ParameterValue>> iterator() {
		if (rawCollection == null) {
			rawCollection = new ArrayList<KeyValuePair<ParameterValue>>();
			if (encodedCollection != null) {
				final StringTokenizer tokens = new StringTokenizer(
						encodedCollection, "&");
				while (tokens.hasMoreTokens()) {
					String currentToken = tokens.nextToken();
					int indexOfEquals = currentToken.indexOf('=');
					String key = currentToken.substring(0, indexOfEquals);
					try {
						ParameterValue value = new StringParameterValue(
								URLDecoder.decode(currentToken
										.substring(indexOfEquals + 1), "utf-8"));
						rawCollection.add(new KeyValuePair<ParameterValue>(
								URLDecoder.decode(key, "utf-8"), value));
					} catch (UnsupportedEncodingException e) {
						throw new RuntimeException(e);
					}
				}
			}
		}
		return rawCollection.iterator();
	}

}
