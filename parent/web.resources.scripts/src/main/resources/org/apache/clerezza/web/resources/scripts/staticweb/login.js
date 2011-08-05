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

 /* two functions to enable TLS Login and Logout in javascript. Works
 for Internet Explorer and Firefox. Sadly missing in other browsers */

function logout(elem) {
    if (document.all == null) {
       if (window.crypto) {
           try{
               window.crypto.logout();
               return false; //firefox ok -- no need to follow the link
           } catch (err) {//Safari, Opera, Chrome -- try with session breaking
           }
       } else { //also try with session breaking
       }
    } else { // MSIE 6+
       document.execCommand('ClearAuthenticationCache');
       return false;
    };
    return true
 }

function login(elem) {
    if (document.all == null){ // FF, Opera, etc
       if (window.crypto) {
         try{
             res = window.crypto.logout();
             return false; // no need to follow link
          } catch (err) {}
       }
    } else {  // MSIE 6+
          document.execCommand('ClearAuthenticationCache');
           return false;
    };
    return true;
}