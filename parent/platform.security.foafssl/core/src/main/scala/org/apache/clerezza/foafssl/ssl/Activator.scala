/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.clerezza.foafssl.ssl

import java.security.KeyStore
import java.util._
import java.io._
import javax.net.ssl.SSLContext
import org.jsslutils.keystores.KeyStoreLoader
import org.jsslutils.sslcontext.X509SSLContextFactory
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext
import org.wymiwyg.jetty.httpservice.{Activator => ServiceActivator}

object Activator {



	def getKeyStoreType(context: BundleContext) = {
		val property = context.getProperty(ServiceActivator.CONTEXT_PROPERTY_KEYSTORE_TYPE);
		if (property != null) {
			property;
		} else {
			"JKS"
		}
	}

	def getKeyStorePath(context: BundleContext) = {
		val property = context.getProperty(ServiceActivator.CONTEXT_PROPERTY_KEYSTORE_PATH);
		if (property != null) {
			property;
		} else {
			new File(new File(System.getProperty("user.home")), ".keystore").getAbsolutePath
		}
	}

	//todo: should check what apps can get access to this. Is it properly protected?
	def getKeyStorePassword(context: BundleContext) = {
		val property = context.getProperty(ServiceActivator.CONTEXT_PROPERTY_KEYSTORE_PASSWORD);
		if (property != null) {
			property;
		} else {
			"password";
		}
	}

	def getServerCertKeyStore(bundleContext: BundleContext): KeyStore = {
		val keyStoreLoader = new KeyStoreLoader
		keyStoreLoader.setKeyStoreType(getKeyStoreType(bundleContext))
		keyStoreLoader.setKeyStorePath(getKeyStorePath(bundleContext))
		keyStoreLoader.setKeyStorePassword(getKeyStorePassword(bundleContext))
      return keyStoreLoader.loadKeyStore();
    }

}

class Activator() {
	import Activator._

	var x509TrustManagerWrapperService: X509TrustManagerWrapperService = null;
	protected def bindX509TrustManagerWrapperService(s: X509TrustManagerWrapperService)  = {
		x509TrustManagerWrapperService = s
	}
	protected def unbindX509TrustManagerWrapperService(s: X509TrustManagerWrapperService)  = {
		x509TrustManagerWrapperService = null
	}
	//registering the SSLContext service should start the https service -- org.wymiwyg.jetty.httpservice.Activator does for example
	protected def activate(context: ComponentContext) = {
    try{
      val bundleContext = context.getBundleContext
      //TODO set jvm default ca-store
      val http = bundleContext.getProperty("org.osgi.service.http.secure.enabled")
      if (http!=null && "true".equals(http)) {
        val sslContextFactory = new X509SSLContextFactory(
          getServerCertKeyStore(bundleContext),
          getKeyStorePassword(bundleContext),
          getServerCertKeyStore(bundleContext)); //getCaKeyStore());
        sslContextFactory
          .setTrustManagerWrapper(x509TrustManagerWrapperService);
        val sslContext = sslContextFactory.buildSSLContext("TLS")
        x509TrustManagerWrapperService.setSslContext(sslContext)

        bundleContext.registerService(classOf[SSLContext].getName, sslContext, new Properties())
        println("Registered SSLContext+")
      }
    }
    catch{
      case e : Exception => println("unable to activate FOAF+SSL")
    }
	}
	
	
	

}


