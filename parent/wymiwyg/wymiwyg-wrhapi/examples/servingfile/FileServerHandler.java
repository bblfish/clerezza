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
package servingfile;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;

import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.ServerBinding;
import org.wymiwyg.wrhapi.WebServerFactory;
import org.wymiwyg.wrhapi.util.MessageBody2Read;

/**
 * @author reto
 *
 */
public class FileServerHandler implements Handler {

	public void handle(Request request, Response response)
			throws HandlerException {
		response.setBody(new MessageBody2Read() {

			public ReadableByteChannel read() throws IOException {
				File file = new File("examples/servingfile/example-file.txt");
		        FileChannel roChannel = new RandomAccessFile(file, "r").getChannel();
		        //or
		        //FileChannel roChannel = new FileInputStream(file).getChannel();
		        return roChannel;
			}			
			
		});
		
	}
	
	/**
	 * Main method starting a server with an instance of this class as Handler
	 * on port 8181
	 * 
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		WebServerFactory.newInstance().startNewWebServer(
				new FileServerHandler(), new ServerBinding() {

					public InetAddress getInetAddress() {
						return null;
					}

					public int getPort() {
						return 8181;
					}

				});
	}

}
