package org.apache.clerezza.uima.utils;

import org.apache.uima.UIMAException;
import org.apache.uima.alchemy.ts.keywords.KeywordFS;
import org.apache.uima.alchemy.ts.language.LanguageFS;
import org.apache.uima.cas.FeatureStructure;
import org.apache.uima.jcas.JCas;
import org.apache.uima.jcas.tcas.Annotation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Facade for querying UIMA external services
 */
public class ExternalServicesFacade {

  private UIMAExecutor uimaExecutor;

  private Map<String, Object> parameterSetting = new HashMap<String, Object>();

  public ExternalServicesFacade() {
    this.uimaExecutor = new UIMAExecutor("ExtServicesAE.xml").withResults();
  }

  public List<String> getTags(String document) throws UIMAException {

    List<String> tags = null;

    try {
      // analyze the document
      uimaExecutor.analyzeDocument(document, "TextKeywordExtractionAEDescriptor.xml", getParameterSetting());

      tags = new ArrayList<String>();

      // get execution results
      JCas jcas = uimaExecutor.getResults();

      // get AlchemyAPI keywords extracted using UIMA
      List<FeatureStructure> keywords = UIMAUtils.getAllFSofType(KeywordFS.type, jcas);

      for (FeatureStructure keywordFS : keywords) {
        tags.add(keywordFS.getStringValue(keywordFS.getType().getFeatureByBaseName("text")));
      }
    } catch (Exception e) {
      throw new UIMAException(e);
    }

    return tags;
  }

  public String getLanguage(String document) throws UIMAException {

    String language = null;

    try {

      // analyze the document
      uimaExecutor.analyzeDocument(document, "TextLanguageDetectionAEDescriptor.xml", getParameterSetting());

      // get execution results
      JCas jcas = uimaExecutor.getResults();

      // extract language Feature Structure using AlchemyAPI Annotator
      FeatureStructure languageFS = UIMAUtils.getSingletonFeatureStructure(LanguageFS.type, jcas);

      language = languageFS.getStringValue(languageFS.getType().getFeatureByBaseName("language"));

    } catch (Exception e) {
      throw new UIMAException(e);
    }

    return language;
  }

  public List<String> getCalaisEntities(String document) throws UIMAException {

    List<String> entities = new ArrayList<String>();

    try {

      // analyze the document
      uimaExecutor.analyzeDocument(document, "OpenCalaisAnnotator.xml", getParameterSetting());

      // get execution results
      JCas jcas = uimaExecutor.getResults();

      // extract entities using OpenCalaisAnnotator
      List<Annotation> calaisAnnotations = UIMAUtils.getAllAnnotationsOfType(org.apache.uima.calais.BaseType.type, jcas);

      // TODO should change return value to a list of richer type wrapping UIMA Annotations
      for (Annotation calaisAnnotation : calaisAnnotations) {
        entities.add(calaisAnnotation.getCoveredText());
      }

    } catch (Exception e) {
      throw new UIMAException(e);
    }
    return entities;
  }

  public Map<String, Object> getParameterSetting() {
    return parameterSetting;
  }

  public void setParameterSetting(Map<String, Object> parameterSetting) {
    this.parameterSetting = parameterSetting;
  }


}