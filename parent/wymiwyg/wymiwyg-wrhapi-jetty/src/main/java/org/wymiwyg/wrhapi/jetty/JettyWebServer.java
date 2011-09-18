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
package org.wymiwyg.wrhapi.jetty;

import java.util.logging.Logger;


import org.eclipse.jetty.server.Server;


import org.wymiwyg.wrhapi.WebServer;


/**
 * @author reto
 *
 */
public class JettyWebServer implements WebServer {
    private final static Logger log = Logger.getLogger(JettyWebServer.class.getName());
    private Server server;

    /**
     * @param server
     */
    JettyWebServer(Server server) {
        this.server = server;
    }

    /* (non-Javadoc)
     * @see org.wymiwyg.wrhapi.WebServer#stop()
     */
    public void stop() {
        try {
            server.stop();

            int i = 0;

            while (server.isStopping()) {
                Thread.sleep(10);

                if ((i % 100) == 0) {
                    log.info("waiting for jetty to stop");
                }

                i++;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
