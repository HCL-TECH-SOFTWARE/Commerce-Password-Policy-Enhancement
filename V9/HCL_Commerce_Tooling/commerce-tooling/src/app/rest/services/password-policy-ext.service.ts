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

/* tslint:disable */
import { Injectable } from '@angular/core';
import { HttpClient, HttpRequest, HttpResponse, HttpHeaders } from '@angular/common/http';
import { BaseService as __BaseService } from '../base-service';
import { ApiConfiguration as __Configuration } from '../api-configuration';
import { StrictHttpResponse as __StrictHttpResponse } from '../strict-http-response';
import { Observable as __Observable } from 'rxjs';
import { map as __map, filter as __filter } from 'rxjs/operators';

@Injectable({
    providedIn: 'root',
})
class ExtPasswordPoliciesService extends __BaseService {
    static readonly createExtPasswordPolicyPath = '/rest/admin/v2/ext-password-policies';
    static readonly updateExtPasswordPolicyByIdPath = '/rest/admin/v2/ext-password-policies/{id}';
    static readonly getExtPasswordPolicyByIdPath = '/rest/admin/v2/ext-password-policies/{id}';
    
    constructor(
        config: __Configuration,
        http: HttpClient
    ) {
        super(config, http);
    }

    /**
      * Create an Ext password policy.
      * @param PasswordPolicy The password policy.
    */
    createExtPasswordPolicyResponse(PasswordPolicyExt: { policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number }): __Observable<__StrictHttpResponse<null>> {
        let __params = this.newParams();
        let __headers = new HttpHeaders();
        let __body: any = null;
        __body = PasswordPolicyExt;
        let req = new HttpRequest<any>(
            'POST',
            this.rootUrl + `/rest/admin/v2/ext-password-policies`,
            __body,
            {
                headers: __headers,
                params: __params,
                responseType: 'json'
            });

        return this.http.request<any>(req).pipe(
            __filter(_r => _r instanceof HttpResponse),
            __map((_r) => {
                return _r as __StrictHttpResponse<null>;
            })
        );
    }

    /**
     * Update an Ext password policy.
     * @param params The `PasswordPoliciesService.UpdateExtPasswordPolicyByIdParams` containing the following parameters:
     *
     * - `PasswordPolicyExt`: The password policy.
     *
     * - `policyPasswordId`: The unique numeric ID for identifying an ext password policy.
    */
    updateExtPasswordPolicyByIdResponse(params: ExtPasswordPoliciesService.UpdateExtPasswordPolicyByIdParams): __Observable<__StrictHttpResponse<null>> {
        let __params = this.newParams();
        let __headers = new HttpHeaders();
        let __body: any = null;
        __body = params.PasswordPolicyExt;

        let req = new HttpRequest<any>(
            'PATCH',
            this.rootUrl + `/rest/admin/v2/ext-password-policies/${params.policyPasswordId}`,
            __body,
            {
                headers: __headers,
                params: __params,
                responseType: 'json'
            });

        return this.http.request<any>(req).pipe(
            __filter(_r => _r instanceof HttpResponse),
            __map((_r) => {
                return _r as __StrictHttpResponse<null>;
            })
        );
    }

    /**
     * Get a password policy.
     * @param params The `PasswordPoliciesService.GetPasswordPolicyByIdParams` containing the following parameters:
     *
     * - `policyPasswordId`: The unique numeric ID for identifying a password policy.
     *
     * - `fields`: The comma-separated set of properties to be returned. If no properties are specified, all properties are returned.
     *
     * - `expand`: The comma-separated set of related resources referenced in the links to be returned. If no related resources are specified, no related resources are returned.
     *
     * - `sort`: The comma-separated set of properties which controls the order of the items being listed, prefixed by either (-) to sort by descending order, or optionally (+) to sort by ascending order. For example, sort=name,-d which means, order the items based on the name value in ascending order, then by the policyPasswordId value in descending order.
     *
     * @return The password policy.
     */
    getExtPasswordPolicyById(params: ExtPasswordPoliciesService.GetExtPasswordPolicyByIdParams): __Observable<{ policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number }> {
        return this.getPasswordPolicyByIdResponse(params).pipe(
            __map(_r => _r.body as { policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number })
        );
    }

    /**
     * Get a password policy.
     * @param params The `ExtPasswordPoliciesService.GetExtPasswordPolicyByIdParams` containing the following parameters:
     *
     * - `policyPasswordId`: The unique numeric ID for identifying a password policy.
     *
     * - `fields`: The comma-separated set of properties to be returned. If no properties are specified, all properties are returned.
     *
     * - `expand`: The comma-separated set of related resources referenced in the links to be returned. If no related resources are specified, no related resources are returned.
     *
     * - `sort`: The comma-separated set of properties which controls the order of the items being listed, prefixed by either (-) to sort by descending order, or optionally (+) to sort by ascending order. For example, sort=name,-d which means, order the items based on the name value in ascending order, then by the policyPasswordId value in descending order.
     *
     * @return The password policy.
    */
    getPasswordPolicyByIdResponse(params: ExtPasswordPoliciesService.GetExtPasswordPolicyByIdParams): __Observable<__StrictHttpResponse<{ policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number }>> {
        let __params = this.newParams();
        let __headers = new HttpHeaders();
        let __body: any = null;

        if (params.fields != null) __params = __params.set('fields', params.fields.toString());
        if (params.expand != null) __params = __params.set('expand', params.expand.toString());
        if (params.sort != null) __params = __params.set('sort', params.sort.toString());
        let req = new HttpRequest<any>(
            'GET',
            this.rootUrl + `/rest/admin/v2/ext-password-policies/${params.policyPasswordId}`,
            __body,
            {
                headers: __headers,
                params: __params,
                responseType: 'json'
            });

        return this.http.request<any>(req).pipe(
            __filter(_r => _r instanceof HttpResponse),
            __map((_r) => {
                return _r as __StrictHttpResponse<{ policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number }>;
            })
        );
    }
}

module ExtPasswordPoliciesService {
    /**
     * Parameters for getPasswordPolicyById
     */
    export interface GetExtPasswordPolicyByIdParams {

        /**
         * The unique numeric ID for identifying a password policy.
         */
        policyPasswordId: string;

        /**
         * The comma-separated set of properties to be returned. If no properties are specified, all properties are returned.
         */
        fields?: string;

        /**
         * The comma-separated set of related resources referenced in the links to be returned. If no related resources are specified, no related resources are returned.
         */
        expand?: string;

        /**
         * The comma-separated set of properties which controls the order of the items being listed, prefixed by either (-) to sort by descending order, or optionally (+) to sort by ascending order. For example, sort=name,-d which means, order the items based on the name value in ascending order, then by the policyPasswordId value in descending order.
         */
        sort?: string;
    }

    /**
     * Parameters for updateExtPasswordPolicyById
    */
    export interface UpdateExtPasswordPolicyByIdParams {

        /**
         * The password policy.
         */
        PasswordPolicyExt: { policyPasswordId?: string, minUCasePassLength?: number, minLCasePassLength?: number, minNonAlphabetic?: number, storeSite?: string, charOrder?: number };

        /**
         * The unique numeric ID for identifying a password policy.
         */
         policyPasswordId: string;
    }
}

export { ExtPasswordPoliciesService }