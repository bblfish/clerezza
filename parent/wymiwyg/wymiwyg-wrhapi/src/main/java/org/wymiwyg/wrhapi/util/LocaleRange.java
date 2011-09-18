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
package org.wymiwyg.wrhapi.util;

import java.util.Locale;


/**
 * @author reto
 *
 */
public class LocaleRange {
    Locale locale;

    LocaleRange() {
        locale = null;
    }

    LocaleRange(Locale locale) {
        this.locale = locale;
    }

    /** Checks is a locale matches this range
     * @param locale
     * @return true id locale matches the range represented by this object, false otherwise
     */
    public boolean match(Locale locale) {
        if (this.locale == null) {
            return true;
        } else {
            return this.locale.getLanguage().equals(locale.getLanguage());
        }
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object other) {
        return equals((LocaleRange) other);
    }

    private boolean equals(LocaleRange other) {
        if (locale == null) {
            return (other.locale == null);
        }

        return locale.equals(other.locale);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        if (locale == null) {
            return 0;
        }

        return locale.hashCode();
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        if (locale == null) {
            return "*";
        }

        return locale.toString();
    }

    /**
     * @return
     */
    public Locale getLocale() {
        return locale;
    }
}
