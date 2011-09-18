/*
 *  Copyright 2009 trialox.org (trialox AG, Switzerland).
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */
package org.wymiwyg.jetty.httpservice.test;

import static org.ops4j.pax.exam.CoreOptions.equinox;
import static org.ops4j.pax.exam.CoreOptions.felix;
import static org.ops4j.pax.exam.CoreOptions.frameworks;
import static org.ops4j.pax.exam.CoreOptions.mavenConfiguration;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.CoreOptions.systemProperty;
import static org.ops4j.pax.exam.container.def.PaxRunnerOptions.dsProfile;
import static org.ops4j.pax.exam.junit.JUnitOptions.junitBundles;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Date;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Inject;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.Configuration;
import org.ops4j.pax.exam.junit.JUnit4TestRunner;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.osgi.util.tracker.ServiceTracker;

@RunWith(JUnit4TestRunner.class)
public class BaseWithPaxExamTest {

	private static final int REQUESTS_PER_THREAD = 1000;
	private static final int THREADS_COUNT = 100;
	final static int PORT = 8383;

	@Inject
	private BundleContext bundleContext;

	@Configuration
	public static Option[] configuration() {
		return options(
				mavenConfiguration(),
				dsProfile(),
				/* profile("felix.webconsole"), */
				junitBundles(),
				frameworks(felix(), equinox()),
				systemProperty("org.osgi.service.http.port").value(
						Integer.toString(PORT)));
	}

	@Test
	public void isRegistered() throws Exception {
		ServiceTracker tracker = new ServiceTracker(bundleContext,
				HttpService.class.getName(), null);
		tracker.open();
		HttpService webServerFactory = (HttpService) tracker
				.waitForService(5000);
		Assert.assertNotNull(webServerFactory);
		Assert.assertEquals(
				"org.eclipse.equinox.http.servlet.internal.HttpServiceImpl",
				webServerFactory.getClass().getName());
		System.out.println("Registering "+new Date());
		webServerFactory.registerServlet("/", servlet, null, null);
		runRequestThreads("http://localhost:" + PORT + "/");
		System.out.println("Unregistering");
		webServerFactory.unregister("/");
		System.out.println("Unregistered "+new Date());

	}

	private void runRequestThreads(String string)
			throws MalformedURLException, InterruptedException {
		final URL url = new URL(string);
		RequestThread[] requestThread = new RequestThread[THREADS_COUNT];
		for (int i = 0; i < THREADS_COUNT; i++) {
			requestThread[i] = new RequestThread(url);
		}
		for (int i = 0; i < THREADS_COUNT; i++) {
			requestThread[i].start();
		}
		int successfulRequests = 0;
		for (int i = 0; i < THREADS_COUNT; i++) {
			requestThread[i].join();
			successfulRequests += requestThread[i].successfulRequests;
		}
		Assert.assertEquals(REQUESTS_PER_THREAD*THREADS_COUNT,successfulRequests);
	}

	final Servlet servlet = new HttpServlet() {

		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			//System.out.println("handling req");
			resp.getWriter().write("Hello World!");
		}

		@Override
		public void init() throws ServletException {
			System.out.println("being initialized");
		}

	};

	static class RequestThread extends Thread {

		
		private URL url;
		int successfulRequests = 0;

		public RequestThread(URL url) {
			this.url = url;
		}

		@Override
		public void run() {
			try {
				for (int i = 0; i < REQUESTS_PER_THREAD; i++) {
					URLConnection urlConnection = url.openConnection();
					InputStream in = urlConnection.getInputStream();
					for (int ch = in.read(); ch != -1; ch = in.read()) {
						//System.out.print((char) ch);
					}
					successfulRequests++;
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

	}
}
