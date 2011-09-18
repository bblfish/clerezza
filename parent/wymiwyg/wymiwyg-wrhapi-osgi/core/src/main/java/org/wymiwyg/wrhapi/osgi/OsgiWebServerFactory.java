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
package org.wymiwyg.wrhapi.osgi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;

import java.util.logging.Logger;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.osgi.service.http.NamespaceException;
import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.MessageBody;
import org.wymiwyg.wrhapi.ServerBinding;
import org.wymiwyg.wrhapi.WebServer;
import org.wymiwyg.wrhapi.WebServerFactory;
import org.wymiwyg.wrhapi.util.MessageBody2Write;

/**
 * This dosn't actually start a webserver but register a servlet with the
 * HTTPService
 *
 * @author reto
 * @scr.component
 * @scr.service interface="org.wymiwyg.wrhapi.WebServerFactory"
 */
public class OsgiWebServerFactory extends WebServerFactory {

	private final static Logger log = Logger.getLogger(OsgiWebServerFactory.class.getName());

	/**
	 * @scr.reference
	 */
	private HttpService httpService;

	private boolean servletRegistered = false;

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.WebServerFactory#startNewWebServer(org.wymiwyg.wrhapi.Handler, org.wymiwyg.wrhapi.ServerBinding)
	 */
	public WebServer startNewWebServer(final Handler handler,
			final ServerBinding configuration) throws IOException {

		Servlet servlet = new HttpServlet() {

			@Override
			protected void service(HttpServletRequest servletRequest,
					final HttpServletResponse servletResponse) throws ServletException, IOException {
				final ResponseImpl responseImpl = new ResponseImpl();
				try {

					handler.handle(new RequestImpl(servletRequest, configuration.getPort()),
							responseImpl);

				} catch (final HandlerException e) {
					responseImpl.setResponseStatus(e.getStatus());
					log.warning("Exception handling request" + e);
					try {
						responseImpl.setBody(new MessageBody2Write() {

							public void writeTo(WritableByteChannel out) throws IOException {
								PrintWriter printWriter = new PrintWriter(Channels.newWriter(out, "utf-8"));
								printWriter.println(e.getMessage());
								printWriter.close();
							}
						});
					} catch (HandlerException e1) {
						throw new RuntimeException(e1);
					}
				}
				final boolean[] headersWritten = new boolean[1];
				OutputStream out = servletResponse.getOutputStream();
				final MessageBody body = responseImpl.getBody();
				if (body != null) {

					WritableByteChannel outChannel = Channels.newChannel(out);
					FirstWriteOrCloseActionChannel fwOut = new FirstWriteOrCloseActionChannel(
							outChannel, new Runnable() {

						public void run() {
							commitStatusAndHeaders(servletResponse,
									responseImpl);
							headersWritten[0] = true;
						}
					});
					body.writeTo(fwOut);
				}

				if (!headersWritten[0]) {
					commitStatusAndHeaders(servletResponse, responseImpl);
				}
				out.close();
			}
		};
		try {
			httpService.registerServlet("/", servlet, null, null);
			servletRegistered = true;
		} catch (ServletException ex) {
			throw new IOException(ex);
		} catch (NamespaceException ex) {
			throw new IOException(ex);
		}

		return new OsgiWebServer(httpService, "/");
	}

	protected void deactivate(ComponentContext context) {
		if (servletRegistered) {
			try {
				httpService.unregister("/");
			} catch (IllegalArgumentException e) {
				//this is thrown by 
				//org.eclipse.equinox.http.servlet.internal.HttpServiceImpl
				//when the underlying adaptor servlet has been restarted
				log.finer(e.toString());
			}
			servletRegistered = false;
		}
	}

	private void commitStatusAndHeaders(
			HttpServletResponse servletResponse,
			ResponseImpl responseImpl) {
		if (responseImpl.getStatus() != null) {
			servletResponse.setStatus(responseImpl.getStatus().getCode());
		} else {
			servletResponse.setStatus(200);
		}
		responseImpl.writeHeaders(servletResponse);
	}
}
