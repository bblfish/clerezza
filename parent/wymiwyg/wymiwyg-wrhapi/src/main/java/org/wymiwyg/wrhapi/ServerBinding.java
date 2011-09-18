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
/*
        (c) Copyright 2005, 2006, Hewlett-Packard Development Company, LP
          [See end of file]
         $Id: ServerBinding.java,v 1.1 2006/09/21 14:40:32 rebach Exp $
*/
package org.wymiwyg.wrhapi;

import java.net.InetAddress;


/**
 * @author reto
 *
 */
public interface ServerBinding {
    /**
     *
     * @return the port to which the server should listen or 0 for the default port
     */
    public int getPort();

    /**
     * @return the <code>InetAddress</code> to which to listen or null if the server should listen to any address
     */
    public InetAddress getInetAddress();
}

