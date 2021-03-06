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
package org.apache.clerezza.uima.utils;

import org.apache.uima.UIMAFramework;
import org.apache.uima.analysis_engine.AnalysisEngine;
import org.apache.uima.analysis_engine.AnalysisEngineDescription;
import org.apache.uima.resource.ResourceInitializationException;
import org.apache.uima.resource.ResourceSpecifier;
import org.apache.uima.util.XMLInputSource;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/**
 * provide the {@link AnalysisEngine} using the default descriptor or using a custom descriptor (absolute)
 * path
 */
public class AEProvider {

  private static String defaultXMLPath;
  private ClassLoader delegateClassloader;

  public AEProvider() {
    defaultXMLPath = "/META-INF/ExtServicesAE.xml"; // if no default is specified use the bundled ext services descriptor
  }

  public AEProvider withDefaultDescriptor(String xmlDescriptorPath) {
    defaultXMLPath = xmlDescriptorPath;
    return this;
  }

  public AEProvider withDelegateClassloader(ClassLoader classLoader) {
    delegateClassloader = classLoader;
    return this;
  }

  /**
   * get an Analysis Engine using the default path (specified in constructor)
   *
   * @return
   * @throws ResourceInitializationException
   *
   */
  public AnalysisEngine getDefaultAE() throws ResourceInitializationException {
    return getAE(defaultXMLPath);
  }

  /**
   * get an Analysis Engine from a different descriptor path
   *
   * @param filePath
   * @return
   * @throws ResourceInitializationException
   *
   */
  public AnalysisEngine getAE(String filePath) throws ResourceInitializationException {
    AnalysisEngine ae = null;
    // get Resource Specifier from XML file
    try {
      URL url = createURLFromPath(filePath);
      XMLInputSource in = new XMLInputSource(url);
      ResourceSpecifier specifier = UIMAFramework.getXMLParser().parseResourceSpecifier(in);
      // create AE here
      ae = UIMAFramework.produceAnalysisEngine(specifier);
    } catch (Exception e) {
      throw new ResourceInitializationException(e);
    }

    return ae;
  }

  private URL createURLFromPath(String filePath) throws MalformedURLException {
    URL url;
    // try classpath
    if (delegateClassloader != null)
      url = delegateClassloader.getResource(filePath);
    else
      url = getClass().getResource(filePath);

    // else try file
    if (url == null) {
      File f = new File(filePath);
      if (f.exists()) {
        url = f.toURI().toURL();
      } else
        throw new MalformedURLException();
    }
    return url;
  }

  public AnalysisEngine getAE(String filePath, Map<String, Object> parameterSettings) throws ResourceInitializationException {
    AnalysisEngine ae;
    // get Resource Specifier from XML file
    try {
      URL url = createURLFromPath(filePath);
      XMLInputSource in = new XMLInputSource(url);

      // eventually add/override descriptor's configuration parameters
      AnalysisEngineDescription desc = UIMAFramework.getXMLParser().parseAnalysisEngineDescription(in);
      for (String parameter : parameterSettings.keySet()) {
        if (desc.getAnalysisEngineMetaData().getConfigurationParameterSettings().getParameterValue(parameter) != null)
          desc.getAnalysisEngineMetaData().getConfigurationParameterSettings().setParameterValue(parameter, parameterSettings.get(parameter));
      }

      // create AE here
      ae = UIMAFramework.produceAnalysisEngine(desc);
    } catch (Exception e) {
      throw new ResourceInitializationException(e);
    }

    return ae;
  }
}