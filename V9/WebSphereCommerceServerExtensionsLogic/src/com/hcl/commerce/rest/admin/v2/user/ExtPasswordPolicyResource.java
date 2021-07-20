/**
	*==================================================
	Copyright [2021] [HCL Technologies]

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0


	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
	*==================================================
**/
package com.hcl.commerce.rest.admin.v2.user;


import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.lang3.StringUtils;
import org.apache.wink.common.http.HttpStatus;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hcl.commerce.passwordpolicy.objects.XPasswordPolicy;
import com.hcl.commerce.passwordpolicy.persistence.XPasswordPolicyDaoImpl;
import com.ibm.commerce.foundation.logging.LoggingHelper;
import com.ibm.commerce.rest.data.AbstractDataResource;

import io.swagger.annotations.ApiOperation;



@Path("ext-password-policies")
public class ExtPasswordPolicyResource extends AbstractDataResource {
   public static final String COPYRIGHT = "(c) Copyright International Business Machines Corporation 1996,2008";
   private static final String CLASSNAME = ExtPasswordPolicyResource.class.getName();
   private static final Logger LOGGER = LoggingHelper.getLogger(ExtPasswordPolicyResource.class);
   private static final String RESOURCE_NAME = "ext-password-policies";
   private static final String POLICY_PASSWORD_ID = "policyPasswordId";
   private static final String POLICY_PASSWORD_ID_DEFAULT = null;
   private static final String MINIMUM_UPPERCASE_LENGTH_PARAM = "minUCasePassLength";
   private static final String MINIMUM_UPPERCASE_LENGTH_DEFAULT = "0";
   private static final String MINIMUM_LOWERCASE_LENGTH_PARAM = "minLCasePassLength";
   private static final String MINIMUM_LOWERCASE_LENGTH_DEFAULT = "0";
   private static final String MINIMUM_NON_ALPHANUMERIC_LENGTH_PARAM = "minNonAlphabetic";
   private static final String MINIMUM_NON_ALPHANUMERIC_LENGTH_DEFAULT = "0";
   private static final String CHARACTER_SEQUENCE_PARAM = "charOrder";
   private static final String CHARACTER_SEQUENCE_DEFAULT = "0";
   private static final String STORE_SITE_PARAM = "storeSite";
   private static final String STORE_SITE_DEFAULT = "1-aurora.com";
   private static final String FIELD1_PARAM = "field1";
   private static final String FIELD2_PARAM = "field2";
   private static final String FIELD3_PARAM = "field3";
   private static final String FIELD4_PARAM = "field4";
   private static final String FIELD5_PARAM = "field5";
   private static final Integer CUSTOM_INTEGER_DEFAULT = 0;


   public String getResourceName() {
      return RESOURCE_NAME;
   }

   @POST
   @Consumes({"application/json"})
   @Produces({"application/json"})
   @ApiOperation(value = "Create resource", hidden = true)
   public Response post(String requestJson) {
      String methodName = "post";
      if (LOGGER.isLoggable(Level.FINER)) {
         LOGGER.entering(CLASSNAME, "post", new Object[]{requestJson});
      }
      Response response = null;

      try {
         ObjectMapper om = new ObjectMapper();
         this.checkAccess();
         Map<String, String> map = (Map)om.readValue(requestJson, new TypeReference<Map<String, String>>() {
         });
         this.validateOrDefaultLongParameter(map, POLICY_PASSWORD_ID, POLICY_PASSWORD_ID_DEFAULT);
         this.validateOrDefaultIntegerParameter(map, MINIMUM_UPPERCASE_LENGTH_PARAM, MINIMUM_UPPERCASE_LENGTH_DEFAULT);
         this.validateOrDefaultIntegerParameter(map, MINIMUM_LOWERCASE_LENGTH_PARAM, MINIMUM_LOWERCASE_LENGTH_DEFAULT);
         this.validateOrDefaultIntegerParameter(map, MINIMUM_NON_ALPHANUMERIC_LENGTH_PARAM, MINIMUM_NON_ALPHANUMERIC_LENGTH_DEFAULT);
         this.validateOrDefaultIntegerParameter(map, CHARACTER_SEQUENCE_PARAM, CHARACTER_SEQUENCE_DEFAULT);
         XPasswordPolicy xpasswordPolicyBean = this.saveXPolicyPassword(map);
		 UriBuilder uriBuilder = UriBuilder.fromResource(this.getClass()).path(xpasswordPolicyBean.getPolicyPasswordId().toString());
		 URI uri = uriBuilder.build(new Object[0]);
		 response = Response.created(uri).build();
         
      } catch (IOException ioex) {
         response = Response.status(HttpStatus.BAD_REQUEST.getCode()).build();
      }
      catch (Exception ex) {
          response = Response.status(HttpStatus.INTERNAL_SERVER_ERROR.getCode()).build();
      }

      if (LOGGER.isLoggable(Level.FINER)) {
         LOGGER.exiting(CLASSNAME, "post", response);
      }

      return response;
   }
   
   /**
    * save data to the X_PLCYPASSWD table
    * */
   private XPasswordPolicy saveXPolicyPassword(Map<String, String> map)   throws Exception {
      String methodName = "saveXPolicyPassword";
      if (LOGGER.isLoggable(Level.FINER)) {
         LOGGER.entering(CLASSNAME, methodName);
      }
      XPasswordPolicy xpasswordPolicyBean = null;
      try {

          xpasswordPolicyBean = new XPasswordPolicy();
          xpasswordPolicyBean.setPolicyPasswordId(Long.valueOf(map.get(POLICY_PASSWORD_ID)));
          xpasswordPolicyBean.setMinUCasePassLength(Integer.valueOf(map.get(MINIMUM_UPPERCASE_LENGTH_PARAM)));
          xpasswordPolicyBean.setMinLCasePassLength(Integer.valueOf(map.get(MINIMUM_LOWERCASE_LENGTH_PARAM)));
          xpasswordPolicyBean.setMinNonAlphabetic(Integer.valueOf(map.get(MINIMUM_NON_ALPHANUMERIC_LENGTH_PARAM)));
          xpasswordPolicyBean.setCharOrder(Integer.valueOf(map.get(CHARACTER_SEQUENCE_PARAM)));
          if(!StringUtils.isBlank(map.get(STORE_SITE_PARAM))) {
         	 xpasswordPolicyBean.setStoreSite(map.get(STORE_SITE_PARAM).trim());
          }
          else {
         	 xpasswordPolicyBean.setStoreSite(STORE_SITE_DEFAULT);
          }
          if(!StringUtils.isBlank(map.get(FIELD1_PARAM))) {
         	 xpasswordPolicyBean.setField1(Integer.valueOf(map.get(FIELD1_PARAM)));
          }
          if(!StringUtils.isBlank(map.get(FIELD2_PARAM))) {
         	 xpasswordPolicyBean.setField2(Integer.valueOf(map.get(FIELD2_PARAM)));
          }
          if(!StringUtils.isBlank(map.get(FIELD3_PARAM))) {
         	 xpasswordPolicyBean.setField3(Integer.valueOf(map.get(FIELD3_PARAM)));
          }
          if(!StringUtils.isBlank(map.get(FIELD4_PARAM))) {
         	 xpasswordPolicyBean.setField4(map.get(FIELD4_PARAM));
          }
          if(!StringUtils.isBlank(map.get(FIELD5_PARAM))) {
         	 xpasswordPolicyBean.setField5(map.get(FIELD5_PARAM));
          }
          XPasswordPolicyDaoImpl xPasswordPolicyDaoImpl = new XPasswordPolicyDaoImpl();
          xPasswordPolicyDaoImpl.persist(xpasswordPolicyBean);

    	  
      }
      catch(Exception ex) {
    	  throw new Exception();
      }
      if (LOGGER.isLoggable(Level.FINER)) {
	         LOGGER.exiting(CLASSNAME, methodName);
	      }
      return xpasswordPolicyBean;
   }
   
   /**
    * validate integer parameter
    * */
   private void validateOrDefaultIntegerParameter(Map<String, String> map, String paramName, String defaultValue) {
      String methodName = "validateOrDefaultIntegerParameter";
      if (LOGGER.isLoggable(Level.FINER)) {
         LOGGER.entering(CLASSNAME, methodName);
      }

      if (map.containsKey(paramName)) {
         Integer.valueOf((String)map.get(paramName));
      } else {
         map.put(paramName, defaultValue);
      }

      if (LOGGER.isLoggable(Level.FINER)) {
         LOGGER.exiting(CLASSNAME, methodName);
      }

   }

   /**
    * validate long parameter
    * */
   private void validateOrDefaultLongParameter(Map<String, String> map, String paramName, String defaultValue) {
	      String methodName = "validateOrDefaultLongParameter";
	      if (LOGGER.isLoggable(Level.FINER)) {
	         LOGGER.entering(CLASSNAME, methodName);
	      }

	      if (map.containsKey(paramName)) {
	         Long.valueOf((String)map.get(paramName));
	      } else {
	         map.put(paramName, defaultValue);
	      }

	      if (LOGGER.isLoggable(Level.FINER)) {
	         LOGGER.exiting(CLASSNAME, methodName);
	      }

	   }
   
}

