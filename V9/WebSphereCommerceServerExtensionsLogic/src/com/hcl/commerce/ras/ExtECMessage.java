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
package com.hcl.commerce.ras;

import com.ibm.commerce.ras.ECMessage;

public class ExtECMessage extends ECMessage{

	public ExtECMessage(String msgKey) {
		super(msgKey);
		// TODO Auto-generated constructor stub
	}
	
	public static final ECMessage _ERR_AUTHENTICATION_MINIMUMUPPERCHAR_PASSWORD = new ECMessage(1L, 1,
			"_ERR_AUTHENTICATION_MINIMUMUPPERCHAR_PASSWORD");
	
	public static final ECMessage _ERR_AUTHENTICATION_MINIMUMLOWERCHAR_PASSWORD = new ECMessage(1L, 1,
			"_ERR_AUTHENTICATION_MINIMUMLOWERCHAR_PASSWORD");
	
	public static final ECMessage _ERR_AUTHENTICATION_MINIMUMSPECIALCHAR_PASSWORD = new ECMessage(1L, 1,
			"_ERR_AUTHENTICATION_MINIMUMSPECIALCHAR_PASSWORD");
	
	public static final ECMessage _ERR_AUTHENTICATION_LETTERSINORDER_PASSWORD = new ECMessage(1L, 1,
			"_ERR_AUTHENTICATION_LETTERSINORDER_PASSWORD");
	
	public static final ECMessage _ERR_AUTHENTICATION_SITEMATCH_PASSWORD = new ECMessage(1L, 1,
			"_ERR_AUTHENTICATION_SITEMATCH_PASSWORD");

}
