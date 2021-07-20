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
package com.hcl.commerce.passwordpolicy.persistence;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import com.hcl.commerce.passwordpolicy.objects.XPasswordPolicy;
import com.ibm.commerce.foundation.persistence.AbstractJPAEntityDaoImpl;

public class XPasswordPolicyDaoImpl  extends AbstractJPAEntityDaoImpl<XPasswordPolicy, Long>{


	public XPasswordPolicyDaoImpl() {
		super(XPasswordPolicy.class);
	}	
	
	@Override
	protected Predicate[] buildPredicates(CriteriaBuilder cb, CriteriaQuery<?> cq, Root<XPasswordPolicy> root,
			String query, Object... queryParameters) {
		List<Predicate> predicateList = new ArrayList<Predicate>();
		if (query != null) {
			if ("XPasswordPolicy.findById".equals(query)) {
				if (queryParameters != null && queryParameters.length == 1) {
						Long policyPasswordId = (Long) queryParameters[0];
						if (policyPasswordId != null) {
							predicateList.add(cb.equal(root.get("policyPasswordId"), policyPasswordId));
						}
					}
				}
		}
		Predicate[] predicates = new Predicate[predicateList.size()];
		predicateList.toArray(predicates);
		return predicates;
	}

}
