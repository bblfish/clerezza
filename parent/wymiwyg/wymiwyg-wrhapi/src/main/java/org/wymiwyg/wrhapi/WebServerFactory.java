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
package org.wymiwyg.wrhapi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

/**
 * @author reto
 * 
 */
public abstract class WebServerFactory {

	



	/**
	 * Starts a new webserver
	 * 
	 * @param handler
	 *            the handler handling all requests
	 * @param serverBinding
	 *            the serverbinding to which the server is connected
	 * @return
	 * @throws IOException
	 */
	public abstract WebServer startNewWebServer(Handler handler,
			ServerBinding serverBinding) throws IOException;

	/**
	 * this returns a WebServerFactory by looking fo a resource
	 * META-INF/services/org.wymiwyg.wrhapi.WebServerFactory containing the FQN
	 * of an implementation.
	 * 
	 * @return a WebServerFactory
	 */
	public static WebServerFactory newInstance() {
		// not using getSystemResources as we use only one provider anymway
		InputStream providerList = ClassLoader.getSystemResourceAsStream(
				"META-INF/services/" + WebServerFactory.class.getName());

		if (providerList == null) {
			throw new RuntimeException("Unable to find provider");
		}

		BufferedReader bufferedReader;

		try {
			bufferedReader = new BufferedReader(new InputStreamReader(
					providerList, "utf-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		try {
			for (String s = bufferedReader.readLine(); s != null; s =
							bufferedReader.readLine()) {
				int poundPos = s.indexOf('#');

				if (poundPos > -1) {
					s = s.substring(0, poundPos);
				}

				s = s.trim();

				Class<?> clazz = Class.forName(s);

				return (WebServerFactory) clazz.newInstance();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		} catch (InstantiationException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}

		throw new RuntimeException("Unable to find provider");
	}
}