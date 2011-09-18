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
package org.wymiwyg.jetty.httpservice;

import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.eclipse.equinox.http.servlet.HttpServiceServlet;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.server.ssl.SslConnector;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;

/**
 * @author reto
 */
@Component(immediate = true)
@Reference(name="sslContext",
		cardinality=ReferenceCardinality.OPTIONAL_MULTIPLE,
		policy=ReferencePolicy.DYNAMIC,
		referenceInterface=SSLContext.class)
public class Activator {


	public static final String CONTEXT_PROPERTY_HTTP_PORT = "org.osgi.service.http.port";
	public static final String CONTEXT_PROPERTY_HTTP_PORT_SECURE = "org.osgi.service.http.port.secure";
	public static final String CONTEXT_PROPERTY_HTTPS_ENABLED = "org.osgi.service.http.secure.enabled";
	public static final String CONTEXT_PROPERTY_HTTP_ENABLED = "org.osgi.service.http.enabled";
	public static final String CONTEXT_PROPERTY_KEYSTORE_PASSWORD = "org.wymiwyg.jetty.httpservice.https.keystore.password";
	public static final String CONTEXT_PROPERTY_KEYSTORE_PATH = "org.wymiwyg.jetty.httpservice.https.keystore.path";
	public static final String CONTEXT_PROPERTY_KEYSTORE_TYPE = "org.wymiwyg.jetty.httpservice.https.keystore.type";
	/**
	 * Context property, one of "none", "want" or "need"
	 */
	public static final String CONTEXT_PROPERTY_CLIENTAUTH = "org.wymiwyg.jetty.httpservice.clientauth";
	private Server server;
	private ComponentContext context;
	private Set<SSLContext> sslContexts = new HashSet<SSLContext>();

	protected void activate(ComponentContext context) throws Exception {
		this.context = context;
		start();
	}
	
	private void start() throws Exception {
		server = new Server();
		BundleContext bundleContext = context.getBundleContext();
		ServletContextHandler servletContext = new ServletContextHandler(ServletContextHandler.SESSIONS);
		servletContext.setContextPath("/");
		server.setHandler(servletContext);
		servletContext.addServlet(new ServletHolder(new HttpServiceServlet()), "/*");

		if (isHttpEnabled(bundleContext)) {
			Connector connector = new SelectChannelConnector();
			connector.setPort(getHttpPort(bundleContext));
			server.addConnector(connector);
		}
		if (isHttpsEnabled(bundleContext)) {
			SslConnector sslConnector = new SslSocketConnector();
			sslConnector.setKeyPassword(getKeyPassword(bundleContext));
			String keyStorePath = bundleContext.getProperty(CONTEXT_PROPERTY_KEYSTORE_PATH);
			if (keyStorePath != null) {
				sslConnector.setKeystore(keyStorePath);
			}
			String keyStoreType = bundleContext.getProperty(CONTEXT_PROPERTY_KEYSTORE_TYPE);
			if (keyStoreType != null) {
				sslConnector.setKeystoreType(keyStoreType);
			}
			if(sslContexts.size() > 0) {
				sslConnector.setSslContext(sslContexts.iterator().next());
			}
			sslConnector.setPort(getHttpsPort(bundleContext));
			String clientAuth = bundleContext.getProperty(CONTEXT_PROPERTY_CLIENTAUTH);
			if ("want".equals(clientAuth)) {
				sslConnector.setWantClientAuth(true);
			} else {
				if ("need".equals(clientAuth)) {
					sslConnector.setNeedClientAuth(true);
				}
			}
			server.addConnector(sslConnector);
		}
		server.start();
	}

	private void stop() throws Exception {
		server.stop();
	}
	private void restart() throws Exception {
		if (server != null) {
			stop();
			start();
		}
	}
	protected void deactivate(ComponentContext context) throws Exception {
		stop();
		server = null;
	}
	
	public void bindSslContext(SSLContext sslContext) {
		sslContexts.add(sslContext);
		if (sslContexts.size() == 1) {
			try {
				restart();
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}
	}
	
	public void unbindSslContext(SSLContext sslContext) throws Exception {
		sslContexts.remove(sslContext);
		restart();
	}

	private boolean isHttpEnabled(BundleContext bundleContext) {
		final String property = bundleContext.getProperty(CONTEXT_PROPERTY_HTTP_ENABLED);
		if (property != null) {
			return Boolean.parseBoolean(property);
		} else {
			return true;
		}
	}

	private boolean isHttpsEnabled(BundleContext bundleContext) {
		final String property = bundleContext.getProperty(CONTEXT_PROPERTY_HTTPS_ENABLED);
		if (property != null) {
			return Boolean.parseBoolean(property);
		} else {
			return false;
		}
	}

	private int getHttpPort(BundleContext bundleContext) {
		final String property = bundleContext.getProperty(CONTEXT_PROPERTY_HTTP_PORT);
		if (property != null) {
			return Integer.parseInt(property);
		} else {
			return 8080;
		}
	}
	
	private int getHttpsPort(BundleContext bundleContext) {
		final String property = bundleContext.getProperty(CONTEXT_PROPERTY_HTTP_PORT_SECURE);
		if (property != null) {
			return Integer.parseInt(property);
		} else {
			return 8443;
		}
	}

	private String getKeyPassword(BundleContext bundleContext) {
		final String property = bundleContext.getProperty(CONTEXT_PROPERTY_KEYSTORE_PASSWORD);
		if (property != null) {
			return property;
		} else {
			return "password";
		}
	}
}
