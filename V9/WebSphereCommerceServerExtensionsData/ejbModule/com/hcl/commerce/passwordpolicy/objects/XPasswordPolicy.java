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
package com.hcl.commerce.passwordpolicy.objects;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import com.ibm.commerce.base.objects.EntityBase;
import com.ibm.commerce.security.Protectable;

/**
 * The persistent class for the X_PLCYPASSWD database table.
 * 
 */
@Entity
@Table(name="X_PLCYPASSWD")
@NamedQueries({	
	@NamedQuery(name="XPasswordPolicy.findById", query="SELECT x FROM XPasswordPolicy x where x.policyPasswordId = :policyPasswordId"),
})
public class XPasswordPolicy extends EntityBase implements Serializable, Protectable{
	
	private static final long serialVersionUID = 1L;
	
	private Long policyPasswordId;
	private Integer minUCasePassLength;
	private Integer minLCasePassLength;
	private Integer minNonAlphabetic;
	private Integer charOrder;
	private String storeSite;
	private Integer field1;
	private Integer field2;
	private Integer field3;
	private String field4;
	private String field5;
	

	/**
	 * Default constructor.
	 */
	public XPasswordPolicy() {
		// TODO Auto-generated constructor stub
	}


	/**
	 * @return the policyPasswordId
	 */
	@Id
	@Column(name="PLCYPASSWD_ID", unique=true, nullable=false)
	public Long getPolicyPasswordId() {
		return policyPasswordId;
	}


	/**
	 * @param policyPasswordId the policyPasswordId to set
	 */
	public void setPolicyPasswordId(Long policyPasswordId) {
		this.policyPasswordId = policyPasswordId;
	}


	/**
	 * @return the minUCasePassLength
	 */
	@Column(name = "MINUCASEPASSWDLEN")
	public Integer getMinUCasePassLength() {
		return minUCasePassLength;
	}


	/**
	 * @param minUCasePassLength the minUCasePassLength to set
	 */
	public void setMinUCasePassLength(Integer minUCasePassLength) {
		this.minUCasePassLength = minUCasePassLength;
	}


	/**
	 * @return the minLCasePassLength
	 */
	@Column(name = "MINLCASEPASSWDLEN")
	public Integer getMinLCasePassLength() {
		return minLCasePassLength;
	}


	/**
	 * @param minLCasePassLength the minLCasePassLength to set
	 */
	public void setMinLCasePassLength(Integer minLCasePassLength) {
		this.minLCasePassLength = minLCasePassLength;
	}

	/**
	 * @return the minNonAlphabetic
	 */
	@Column(name = "MINNONALPHABETIC")
	public Integer getMinNonAlphabetic() {
		return minNonAlphabetic;
	}
	/**
	 * @param minNonAlphabetic the minNonAlphabetic to set
	 */
	public void setMinNonAlphabetic(Integer minNonAlphabetic) {
		this.minNonAlphabetic = minNonAlphabetic;
	}
	
	/**
	 * @return the charOrder
	 */
	@Column(name = "CHARORDER")
	public Integer getCharOrder() {
		return charOrder;
	}

	/**
	 * @param charOrder the charOrder to set
	 */
	public void setCharOrder(Integer charOrder) {
		this.charOrder = charOrder;
	}

	/**
	 * @return the storeSite
	 */
	@Column(name = "STORESITE")
	public String getStoreSite() {
		return storeSite;
	}


	/**
	 * @param storeSite the storeSite to set
	 */
	public void setStoreSite(String storeSite) {
		this.storeSite = storeSite;
	}




	/**
	 * @return the field1
	 */
	@Column(name = "FIELD1")
	public Integer getField1() {
		return field1;
	}


	/**
	 * @param field1 the field1 to set
	 */
	public void setField1(Integer field1) {
		this.field1 = field1;
	}


	/**
	 * @return the field2
	 */
	@Column(name = "FIELD2")
	public Integer getField2() {
		return field2;
	}


	/**
	 * @param field2 the field2 to set
	 */
	public void setField2(Integer field2) {
		this.field2 = field2;
	}


	/**
	 * @return the field3
	 */
	@Column(name = "FIELD3")
	public Integer getField3() {
		return field3;
	}


	/**
	 * @param field3 the field3 to set
	 */
	public void setField3(Integer field3) {
		this.field3 = field3;
	}


	/**
	 * @return the field4
	 */
	@Column(name = "FIELD4")
	public String getField4() {
		return field4;
	}


	/**
	 * @param field4 the field4 to set
	 */
	public void setField4(String field4) {
		this.field4 = field4;
	}


	/**
	 * @return the field5
	 */
	@Column(name = "FIELD5")
	public String getField5() {
		return field5;
	}


	/**
	 * @param field5 the field5 to set
	 */
	public void setField5(String field5) {
		this.field5 = field5;
	}
	
}
