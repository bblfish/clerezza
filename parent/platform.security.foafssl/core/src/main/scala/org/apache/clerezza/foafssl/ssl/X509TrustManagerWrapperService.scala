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

import org.jsslutils.sslcontext.X509TrustManagerWrapper
import org.osgi.service.component.ComponentContext
import org.apache.clerezza.foafssl.auth.X509Claim
import org.slf4j.scala.Logging
import org.jsslutils.sslcontext.trustmanagers.TrustAllClientsWrappingTrustManager
import javax.net.ssl.{SSLSession, SSLContext, X509TrustManager}
import javax.security.auth.Subject
import com.google.common.collect.MapMaker
import java.util.concurrent.TimeUnit
import java.util.{Date, Arrays}
import javax.security.auth.x500.X500Principal
import java.security.cert._

object LogoutEnabledTM {

	/**
	 * A class to pass a bit of error metadata around. We put the
	 * certificate in here, to help in debugging, as working with the signature of a certificiate
	 * is too limited
	 */
	class Err(val start: Date, val cert: X509Certificate, error: CertificateException, var attempt: Int = 1) {
		protected var inc: Int = 1000 * 60 * 3 // 3 minutes is the default
		def increase(millis: Int) {
			inc = inc + millis
		}

		def getException(): CertificateException = {
			attempt match {
				case 0 => error
				case 1 => new CertificateNotYetValidException()
				case 2 => new CertificateRevokedException(new Date(),CRLReason.UNSPECIFIED,new X500Principal("someone"),new java.util.HashMap[String,Extension])
				case 3 => new CertificateExpiredException()
				case _ => error
			}
		}



		//Some annoying browsers send the same certificate again and again even when one selects a different one
		def stillValid() = {
			//valid only 2ce and no more than 3 minutes (though this should depend on error type)
			val res = attempt>0 && System.currentTimeMillis() < start.getTime + inc
	      attempt = attempt-1
			res
		}
	}

	/**
	 * a Sig class. contents are never meant to change and we only need it
	 * for lookup
	 *
	 */
	class Sig(val bytes: Array[Byte]) {

		lazy val hash = Arrays.hashCode(bytes)

		override def hashCode() = hash

		override def equals(other: Any) = other match {
			case othersig: Sig => Arrays.equals(bytes, othersig.bytes)
			case _ => false
		}

	}

}

class X509TrustManagerWrapperService() extends X509TrustManagerWrapper with Logging {

	import LogoutEnabledTM._
	override def wrapTrustManager(trustManager: X509TrustManager): X509TrustManager =  new LogoutEnabledTM(trustManager)

	//all threads should use the same trust manager, so be careful of synchronisation issues
	class LogoutEnabledTM(trustManager: X509TrustManager) extends TrustAllClientsWrappingTrustManager(trustManager) {

			//At this level we just check if there are webids  //this is called whenever new sessions are created (I am pretty sure)
			override def checkClientTrusted(chain: Array[X509Certificate], authType: String): Unit = {
				try {
					val sig = new Sig(chain(0).getSignature)
					toBreakKeys.get(sig) match {
						case err: Err => {
							if (err.stillValid()) {
								logger.info("broke connection")
								throw err.getException()
							} else toBreakKeys.remove(sig)
						}
						case null => {
							logger.info("new connection started")
						}
					}
					return
				} catch {
					case ce: CertificateException => throw ce
					case ex: Throwable => {
						logger.info("can't check client", ex)
						throw new CertificateException("cannot check client" + ex.getMessage);
					}
				}
			}
		}

	protected def activate(context: ComponentContext) = { }

	val toBreakKeys = new MapMaker().expireAfterWrite(3,TimeUnit.MINUTES).makeMap[Sig,Err]()

	var sslContext: SSLContext = _

	/**
	 * set the ssl context on which this trust manager is working
	 */
	def setSslContext(sslContext: SSLContext) {
		this.sslContext = sslContext
	}





	/**
	 * taken from TypeUtil in jetty
	 */
	def fromHexString(s: String): Array[Byte] = {
		if (s.length % 2 != 0) throw new IllegalArgumentException(s)
		val array = new Array[Byte](s.length / 2)
		for (i <- 0 until array.length) {
			var b: Int = Integer.parseInt(s.substring(i * 2, (i * 2) + 2), 16)
			array(i) = (0xff & b).asInstanceOf[Byte]
		}
		return array
	}

	/**
	 * clears a break on this certificate
	 * @param a certificate signature, identifying the certificate
	 */
	def clearBreak(certSig: Array[Byte]) {
		 toBreakKeys.remove(new Sig(certSig))
	}


	/**
	 * break the ssl session and set things up so that the next time a certificate is presented in a connection it will
	 * be returned
	 *
	 * This must be called by the thread
	 *
	 * @param session identifier string as returned by servlets in their "javax.servlet.request.ssl_session_id" attribute
	 * @param the subject for which the connection must be broken - this contains the X509 certs
	 */
	def breakConnectionFor(sessionId: String, subject: Subject) {
		val sessionBA = fromHexString(sessionId)
		val session = sslContext.getServerSessionContext.getSession(sessionBA)
		breakConnectionFor(session, subject)
	}

	/**
	 * break the ssl session and set things up so that the next time a certificate is presented in a connection it will
	 * be returned
	 *
	 * @param session to invalidate
	 * @param the subject for which the connection must be broken - this contains the X509 certs
	 */
	def breakConnectionFor(session: SSLSession, subject: Subject) {
		import collection.JavaConversions._
		if (session != null) session.invalidate()

		val x509claims = subject.getPublicCredentials(classOf[X509Claim])
		for (claim <- x509claims) {
			val err= if (claim.tooEarly) new CertificateNotYetValidException()
			         else if (claim.tooLate) new CertificateExpiredException()
			         else new CertificateException()
			toBreakKeys.put(new Sig(claim.cert.getSignature), new Err(new Date(),claim.cert, err))
		}
	}

}

