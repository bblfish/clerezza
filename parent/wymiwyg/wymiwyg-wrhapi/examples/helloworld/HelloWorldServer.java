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
package helloworld;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;

import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.ServerBinding;
import org.wymiwyg.wrhapi.WebServer;
import org.wymiwyg.wrhapi.WebServerFactory;
import org.wymiwyg.wrhapi.util.MessageBody2Write;

/**
 * A simple HelloWorld-example.
 */
public class HelloWorldServer {

	/**
	 * @param args
	 *            no arguments are supported
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		ServerBinding serverBinding = new ServerBinding() {

			public InetAddress getInetAddress() {
				return null;
			}

			public int getPort() {
				return 8080;
			}

		};
		Handler handler = new Handler() {

			public void handle(Request request, Response response)
					throws HandlerException {
				response.setHeader(HeaderName.CONTENT_TYPE,
						"text/plain; charset=utf-8");
				response.setBody(new MessageBody2Write() {
					public void writeTo(WritableByteChannel out)
							throws IOException {
						PrintWriter writer = new PrintWriter(Channels
								.newWriter(out, "utf-8"));
						writer.println("Hello World!");
						writer.close();
					}
				});
			}
		};
		WebServer webServer = WebServerFactory.newInstance().startNewWebServer(
				handler, serverBinding);
		System.out.println("Webserver started, press enter to stop it");
		System.in.read();
		webServer.stop();
		System.out.println("Webserver stopped");

	}

}
