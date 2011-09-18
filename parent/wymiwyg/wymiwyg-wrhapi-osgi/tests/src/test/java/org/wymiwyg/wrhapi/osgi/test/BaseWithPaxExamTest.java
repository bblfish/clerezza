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
package org.wymiwyg.wrhapi.osgi.test;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Inject;
import static org.ops4j.pax.exam.CoreOptions.*;
import static org.ops4j.pax.exam.container.def.PaxRunnerOptions.*;
import static org.ops4j.pax.exam.junit.JUnitOptions.*;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.Configuration;
import org.ops4j.pax.exam.junit.JUnit4TestRunner;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.wymiwyg.wrhapi.WebServerFactory;
import org.wymiwyg.wrhapi.osgi.OsgiWebServerFactory;
import org.wymiwyg.wrhapi.test.BaseTests;

@RunWith(JUnit4TestRunner.class)
public class BaseWithPaxExamTest extends BaseTests {

	@Inject
	private BundleContext bundleContext;

	@Configuration
	public static Option[] configuration() {
		final String port = Integer.toString(BaseTests.serverBinding.getPort());
		return options(
				mavenConfiguration(),
				mavenBundle().groupId("org.wymiwyg").artifactId("wrhapi-osgi").versionAsInProject(),
				mavenBundle().groupId("org.wymiwyg").artifactId("wrhapi").versionAsInProject(),
				mavenBundle().groupId("org.wymiwyg").artifactId("wrhapi-testing").versionAsInProject(),
				mavenBundle().groupId("org.wymiwyg").artifactId("wymiwyg-commons-core").versionAsInProject(),
				wrappedBundle(maven("com.ibm.icu", "icu4j")),
				mavenBundle().groupId("org.apache.httpcomponents").artifactId("httpclient-osgi").versionAsInProject(),
				mavenBundle().groupId("org.apache.httpcomponents").artifactId("httpcore-osgi"),
				dsProfile(),
				webProfile(),
				//profile("felix.webconsole"),
				junitBundles(),
				frameworks(
				felix(), equinox()),
				systemProperty("org.osgi.service.http.port").value(
				port));
	}

	@Test
	public void isRegistered() throws Exception {
		ServiceTracker tracker = new ServiceTracker(bundleContext,
				WebServerFactory.class.getName(), null);
		tracker.open();
		WebServerFactory webServerFactory = (WebServerFactory) tracker.waitForService(5000);
		Assert.assertNotNull(webServerFactory);
		Assert.assertEquals(OsgiWebServerFactory.class, webServerFactory.getClass());

		
	}

	@Override
	protected WebServerFactory createServer() {
		try {
			ServiceTracker tracker = new ServiceTracker(bundleContext, WebServerFactory.class.getName(), null);
			tracker.open();
			WebServerFactory webServerFactory = (WebServerFactory) tracker.waitForService(5000);
			return webServerFactory;
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new RuntimeException(ex);
		}

	}
}
