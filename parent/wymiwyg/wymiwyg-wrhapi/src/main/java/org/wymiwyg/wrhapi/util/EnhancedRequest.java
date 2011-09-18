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
package org.wymiwyg.wrhapi.util;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.StringTokenizer;


import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.URIScheme;

/**
 * This is a Request-implemntation that provides additional methods. It is
 * implemented to wrap an existing Request providing a minimal performance
 * overhead.
 * 
 * @author reto
 */
public class EnhancedRequest extends RequestWrapper {

	private String host;

	private int port = -1;

	/**
	 * Creates an EnhancedRequest from a Request.
	 * 
	 * @param base the base request to be decorated
	 * 
	 */
	public EnhancedRequest(Request base) {
		super(base);
	}

	/**
	 * reconstructs the requested URL
	 * 
	 * @return the requested URL including all get parameters
	 * @throws HandlerException
	 */
	public URL getFullRequestURL() throws HandlerException {
		String requestURIString = getRequestURI().toString();

		// this is because of strange requests see fom davfs2
		if (requestURIString.equals("//")) {
			requestURIString = "/";
		}

		try {
			return new URL(getRootURL(), requestURIString);
		} catch (MalformedURLException e) {
			throw new HandlerException(e);
		}
	}

	/**
	 * Reconstructs the URL of the request omitting the query part.
	 * 
	 * @return
	 * @throws HandlerException
	 */
	public URL getRequestURLWithoutParams() throws HandlerException {
		String requestURIString = getRequestURI().getPath();

		// this is because of strange requests see fom davfs2
		if (requestURIString.equals("//")) {
			requestURIString = "/";
		}

		try {
			return new URL(getRootURL(), requestURIString);
		} catch (MalformedURLException e) {
			throw new HandlerException(e);
		}
	}

	/**
	 * @return the root URL, omitting the default-port (even if the host-header
	 *         value contains it)
	 * @throws HandlerException
	 * 
	 */
	public URL getRootURL() throws HandlerException {
		URIScheme scheme = getScheme();
		int port = getRequestPort();
		StringBuffer url = new StringBuffer();
		url.append(scheme.getStringRepresentation());
		url.append("://");
		url.append(getHost());

		if ((port > 0)
				&& ((scheme == URIScheme.HTTP && (port != 80)) || (scheme == URIScheme.HTTPS && (port != 443)))) {
			url.append(':');
			url.append(port);
		}

		try {
			return new URL(url.toString());
		} catch (MalformedURLException e) {
			throw new HandlerException(e);
		}
	}

	/**
	 * @return the port extracted from the Host-Header, if no-host-header is
	 *         available the value of getPort() is returned. if the host header
	 *         doesn't contain a port the default port for the scheme is
	 *         returned.
	 * @throws HandlerException
	 */
	private int getRequestPort() throws HandlerException {
		if (port == -1) {
			try {
				String hostHeader = getHeaderValues(HeaderName.HOST)[0];
				int colonPos = hostHeader.indexOf(':');
				if (colonPos != -1) {
					port = Integer.parseInt(hostHeader.substring(colonPos + 1));
				} else {
					port = getDefaultPortForScheme(getScheme());
				}
			} catch (ArrayIndexOutOfBoundsException e) {
				port = getPort();
			}
		}
		return port;
	}

	/**
	 * @param scheme
	 * @return
	 */
	private int getDefaultPortForScheme(URIScheme scheme) {
		if (scheme == URIScheme.HTTP) {
			return 80;
		}
		if (scheme == URIScheme.HTTPS) {
			return 443;
		}
		if (scheme == URIScheme.HTTPSY) {
			return 80;
		}
		throw new RuntimeException("unsupported scheme");
	}

	/**
	 * @return the cookes in this request
	 * @throws HandlerException
	 */
	public Cookie[] getCookies() throws HandlerException {
		String[] headers = getHeaderValues(HeaderName.COOKIE);

		Collection<Cookie> resultCollection = new ArrayList<Cookie>();

		for (int i = 0; i < headers.length; i++) {
			StringTokenizer tokens = new StringTokenizer(headers[i], ";,");

			while (tokens.hasMoreElements()) {
				try {
					resultCollection.add(new Cookie(tokens.nextToken()));
				} catch (InvalidCookieException e) {
					throw new HandlerException(e);
				}
			}
		}

		return resultCollection.toArray(new Cookie[resultCollection.size()]);
	}

	/**
	 * @return
	 * @throws HandlerException
	 */
	private String getHost() throws HandlerException {
		if (host == null) {
			try {
				host = getHeaderValues(HeaderName.HOST)[0];
			} catch (ArrayIndexOutOfBoundsException e) {
				throw new HandlerException("No host header");
			}

			int colonPos = host.indexOf(':');

			if (colonPos != -1) {
				host = host.substring(0, colonPos);
			}
		}

		return host;
	}

	/**
	 * The accept-header entries sorted by q-value
	 * 
	 * @return an iterator of the AcceptHeaderEntryS
	 * @throws HandlerException
	 */
	public Iterator<AcceptHeaderEntry> getAccept() throws HandlerException {
		String[] acceptStrings = getHeaderValues(HeaderName.ACCEPT);

		return new AcceptHeaderIterator(acceptStrings);
	}

	/**
	 * The accept-language-header entries sorted by q-value
	 * 
	 * @return
	 * @throws HandlerException
	 */
	public AcceptLanguagesIterator getAcceptLanguages() throws HandlerException {
		String[] acceptStrings = getHeaderValues(HeaderName.ACCEPT_LANGUAGE);

		return new AcceptLanguagesIterator(acceptStrings);
	}
}
