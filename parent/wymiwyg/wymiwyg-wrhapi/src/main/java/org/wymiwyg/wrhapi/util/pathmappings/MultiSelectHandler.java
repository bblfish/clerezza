/*
 * Copyright 2008 WYMIWYG (http://wymiwyg.org)
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

package org.wymiwyg.wrhapi.util.pathmappings;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.util.HashSet;
import java.util.Set;
import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.util.MessageBody2Write;



/**
 *
 * @author reto
 */
class MultiSelectHandler implements Handler {

	private Set<String> options = new HashSet<String>();

	public void handle(Request request, Response response) throws HandlerException {
		
		final String absPath = request.getRequestURI().getAbsPath().substring(1);
		
		response.setBody(new MessageBody2Write() {

			public void writeTo(WritableByteChannel out) throws IOException {
				PrintWriter writer = new PrintWriter(Channels.newWriter(out, "utf-8"));
				writer.println("<html>");
				writer.println("<body>");
				writer.println("<h1>Multiple handlers configured for this path</h1>");
				for (String option : options) {
					writer.println("<a href="+option+absPath+">"+option+absPath+"</a>");
					writer.println("<br />");
				}
				writer.println("</body>");
				writer.println("</html>");
				writer.flush();
			}
		});
	}

	void addOption(String option) {
		options.add(option);
	}



}
