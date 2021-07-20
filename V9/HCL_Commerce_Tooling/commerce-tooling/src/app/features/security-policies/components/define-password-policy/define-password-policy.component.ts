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

import { Component, OnInit, Input, Output, EventEmitter, AfterViewInit, ViewChild, ElementRef } from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { FormGroup, FormControl } from "@angular/forms";
import { TranslateService } from "@ngx-translate/core";
import { MatStepper, MatStep } from "@angular/material/stepper";
import { MatSlideToggle } from "@angular/material";
import { AlertService } from "../../../../services/alert.service";
import { SecurityPoliciesMainService } from "../../services/security-policies-main.service";

@Component({
	templateUrl: "./define-password-policy.component.html",
	styleUrls: ["./define-password-policy.component.scss"],
	selector: "hc-define-password-policy"
})
export class DefinePasswordPolicyComponent implements OnInit, AfterViewInit {
	@Input() stepper: MatStepper;
	@Input() step: MatStep;
	@Input() mode: String;

	@Input() maximumConsecutiveType: FormControl;
	@Input() minimumAlphabetic: FormControl;
	@Input() maximumInstances: FormControl;
	@Input() minimumNumeric: FormControl;
	@Input() maximumLifetime: FormControl;
	@Input() minimumPasswordLength: FormControl;
	/* Password Policy Enhancement Start */
	@Input() minUCasePassLength: FormControl;
	@Input() minLCasePassLength: FormControl;
	@Input() minNonAlphabetic: FormControl;
	@Input() storeSite: FormControl;
	@Input() charOrder: FormControl;
	/* Password Policy Enhancement End */
	@Input() reusePassword: FormControl;
	@Input() matchUserId: FormControl;
	@Output() save: EventEmitter<any> = new EventEmitter<any>();
	@ViewChild("matchUserIdInput", {static: false}) matchUserIdInput: MatSlideToggle;

	passwordPolicyForm: FormGroup | any;

	/* Password Policy Enhancement Start */
	charOrderValues = [
		{
			content: "0",
			value: 0
		},
		{
			content: "1",
			value: 1
		},
	]
	/* Password Policy Enhancement End */

	reusePasswordValues = [
		{
			content: "0",
			value: 1
		},
		{
			content: "1",
			value: -1
		},
		{
			content: "2",
			value: -2
		},
		{
			content: "3",
			value: -3
		},
		{
			content: "4",
			value: -4
		},
		{
			content: "5",
			value: -5
		},
		{
			content: "6",
			value: -6
		},
		{
			content: "7",
			value: -7
		},
		{
			content: "8",
			value: -8
		},
		{
			content: "9",
			value: -9
		},
		{
			content: "10",
			value: -10
		}
	];

	constructor(
			private router: Router,
			private route: ActivatedRoute,
			private translateService: TranslateService,
			private alertService: AlertService,
			private securityPoliciesMainService: SecurityPoliciesMainService) { }

	ngOnInit() {
		this.createFormControls();
		this.createForm();
		if (this.mode === "edit") {
			this.securityPoliciesMainService.loadCurrentPasswordPolicy(Number(this.route.snapshot.params.id)).subscribe(
				response => {
					this.setValues();
					this.step.ngOnChanges();
				}
			);
		} else {
			this.setValues();
		}
	}

	ngAfterViewInit() {
		this.step.stepControl = this.passwordPolicyForm;
		setTimeout(() => {
			this.matchUserIdInput.focus();
		}, 250);
	}

	next() {
		this.passwordPolicyForm.markAllAsTouched();
		this.alertService.clear();
		if (this.passwordPolicyForm.valid) {
			this.stepper.next();
		} else {
			this.translateService.get("SECURITY_POLICIES.INPUT_ERROR").subscribe((message: string) => {
				this.alertService.error({message});
			});
		}
	}

	triggerSave() {
		this.passwordPolicyForm.markAllAsTouched();
		this.save.emit(null);
	}

	validateMaximumConsecutiveType() {
		this.securityPoliciesMainService.passwordPolicyData.maximumConsecutiveType = this.maximumConsecutiveType.value;
	}

	validateMinimumAlphabetic() {
		this.securityPoliciesMainService.passwordPolicyData.minimumAlphabetic = this.minimumAlphabetic.value;
	}

	validateMaximumInstances() {
		this.securityPoliciesMainService.passwordPolicyData.maximumInstances = this.maximumInstances.value;
	}

	validatMinimumNumeric() {
		this.securityPoliciesMainService.passwordPolicyData.minimumNumeric = this.minimumNumeric.value;
	}

	validateMaximumLifetime() {
		this.securityPoliciesMainService.passwordPolicyData.maximumLifetime = this.maximumLifetime.value;
	}

	validateReusePassword(value) {
		this.securityPoliciesMainService.passwordPolicyData.reusePassword = value;
	}

	validateMinimumPasswordLength() {
		this.securityPoliciesMainService.passwordPolicyData.minimumPasswordLength = this.minimumPasswordLength.value;
	}

	/* Password Policy Enhancement Start */
	validateMinUCasePassLength() {
		this.securityPoliciesMainService.passwordPolicyData.minUCasePassLength = this.minUCasePassLength.value;
	}

	validateMinLCasePassLength() {
		this.securityPoliciesMainService.passwordPolicyData.minLCasePassLength = this.minLCasePassLength.value;
	}

	validateMinNonAlphabetic() {
		this.securityPoliciesMainService.passwordPolicyData.minNonAlphabetic = this.minNonAlphabetic.value;
	}

	validateStoreSite() {
		this.securityPoliciesMainService.passwordPolicyData.storeSite = this.storeSite.value;
	}

	validateCharOrder(value) {
		this.securityPoliciesMainService.passwordPolicyData.charOrder = value;
	}
	/* Password Policy Enhancement End */

	toggleMatchUserId(matchUserId) {
		this.securityPoliciesMainService.passwordPolicyData.matchUserId = matchUserId.checked ? 1 : 0;
	}

	private setValues() {
		if (this.securityPoliciesMainService.passwordPolicyData === null) {
			this.securityPoliciesMainService.passwordPolicyData = {
				maximumConsecutiveType: 4,
				minimumAlphabetic: 1,
				maximumInstances: 3,
				minimumNumeric: 1,
				maximumLifetime: 90,
				minimumPasswordLength: 8,
				/* Password Policy Enhancement Start */
				minUCasePassLength: 0,
				minLCasePassLength: 0,
				minNonAlphabetic: 0,
				storeSite: "1-aurora.com",
				charOrder: 0,
				/* Password Policy Enhancement End */
				reusePassword: 1,
				matchUserId: 0
			};
		}
		const passwordPolicyData = this.securityPoliciesMainService.passwordPolicyData;
		this.maximumConsecutiveType.setValue(passwordPolicyData.maximumConsecutiveType);
		this.minimumAlphabetic.setValue(passwordPolicyData.minimumAlphabetic);
		this.maximumInstances.setValue(passwordPolicyData.maximumInstances);
		this.minimumNumeric.setValue(passwordPolicyData.minimumNumeric);
		this.maximumLifetime.setValue(passwordPolicyData.maximumLifetime);
		this.minimumPasswordLength.setValue(passwordPolicyData.minimumPasswordLength);
		/* Password Policy Enhancement Start */
		this.minUCasePassLength.setValue(passwordPolicyData.minUCasePassLength);
		this.minLCasePassLength.setValue(passwordPolicyData.minLCasePassLength);
		this.minNonAlphabetic.setValue(passwordPolicyData.minNonAlphabetic);
		this.storeSite.setValue(passwordPolicyData.storeSite);
		this.charOrder.setValue(passwordPolicyData.charOrder);
		/* Password Policy Enhancement End */
		this.reusePassword.setValue(passwordPolicyData.reusePassword);
		this.matchUserId.setValue(passwordPolicyData.matchUserId === 0 ? false : true);
	}

	private createFormControls() {
		this.maximumConsecutiveType = new FormControl(null, maximumConsecutiveType => {
			let errors = null;
			if (maximumConsecutiveType.value !== "" && maximumConsecutiveType.value !== null &&
					(isNaN(maximumConsecutiveType.value) || Number(maximumConsecutiveType.value) < 0)) {
				errors = {
					invalidMaximumConsecutiveType: true
				};
			}
			return errors;
		});
		this.minimumAlphabetic = new FormControl(null, minimumAlphabetic => {
			let errors = null;
			if (minimumAlphabetic.value !== "" && minimumAlphabetic.value !== null &&
					(isNaN(minimumAlphabetic.value) || Number(minimumAlphabetic.value) < 0)) {
				errors = {
					invalidMinimumAlphabetic: true
				};
			}
			return errors;
		});
		this.maximumInstances = new FormControl(null, maximumInstances => {
			let errors = null;
			if (maximumInstances.value !== "" && maximumInstances.value !== null &&
					(isNaN(maximumInstances.value) || Number(maximumInstances.value) < 0)) {
				errors = {
					invalidMaximumInstances: true
				};
			}
			return errors;
		});
		this.minimumNumeric = new FormControl(null, minimumNumeric => {
			let errors = null;
			if (minimumNumeric.value !== "" && minimumNumeric.value !== null &&
					(isNaN(minimumNumeric.value) || Number(minimumNumeric.value) < 0)) {
				errors = {
					invalidMinimumNumeric: true
				};
			}
			return errors;
		});
		this.maximumLifetime = new FormControl(null, maximumLifetime => {
			let errors = null;
			if (maximumLifetime.value !== "" && maximumLifetime.value !== null &&
					(isNaN(maximumLifetime.value) || Number(maximumLifetime.value) < 0)) {
				errors = {
					invalidMaximumLifetime: true
				};
			}
			return errors;
		});
		this.minimumPasswordLength = new FormControl(null, minimumPasswordLength => {
			let errors = null;
			if (minimumPasswordLength.value !== "" && minimumPasswordLength.value !== null &&
					(isNaN(minimumPasswordLength.value) || Number(minimumPasswordLength.value) < 0)) {
				errors = {
					invalidMinimumPasswordLength: true
				};
			}
			return errors;
		});
		/* Password Policy Enhancement Start */
		this.minUCasePassLength = new FormControl(null, minUCasePassLength => {
			let errors = null;
			if (minUCasePassLength.value !== "" && minUCasePassLength.value !== null &&
					(isNaN(minUCasePassLength.value) || Number(minUCasePassLength.value) < 0)) {
				errors = {
					invalidMinUCasePassLength: true
				};
			}
			return errors;
		});
		this.minLCasePassLength = new FormControl(null, minLCasePassLength => {
			let errors = null;
			if (minLCasePassLength.value !== "" && minLCasePassLength.value !== null &&
					(isNaN(minLCasePassLength.value) || Number(minLCasePassLength.value) < 0)) {
				errors = {
					invalidMinLCasePassLength: true
				};
			}
			return errors;
		});
		this.minNonAlphabetic = new FormControl(null, minNonAlphabetic => {
			let errors = null;
			if (minNonAlphabetic.value !== "" && minNonAlphabetic.value !== null &&
					(isNaN(minNonAlphabetic.value) || Number(minNonAlphabetic.value) < 0)) {
				errors = {
					invalidMinNonAlphabetic: true
				};
			}
			return errors;
		});
		this.storeSite = new FormControl(null, storeSite => {
			let errors = null;
			if (storeSite.value) {
				const regexToValidateStoreSite = /^([0-9]+-(((https?|ftp|smtp):\/\/)?(www.)?[a-z0-9]+\.[a-z]+(\/[a-zA-Z0-9#]+\/?)*)+\|)*[0-9]+-(((https?|ftp|smtp):\/\/)?(www.)?[a-z0-9]+\.[a-z]+(\/[a-zA-Z0-9#]+\/?)*)$/gm;
				if(!storeSite.value.match(regexToValidateStoreSite)) {
					errors = {
						invalidStoreSite: true
					};
				}
			}
			return errors;
		});
		this.charOrder = new FormControl(null);
		/* Password Policy Enhancement End */
		this.reusePassword = new FormControl(null);
		this.matchUserId = new FormControl(null);
	}

	private createForm() {
		this.passwordPolicyForm = new FormGroup({
			maximumConsecutiveType: this.maximumConsecutiveType,
			minimumAlphabetic: this.minimumAlphabetic,
			maximumInstances: this.maximumInstances,
			minimumNumeric: this.minimumNumeric,
			maximumLifetime: this.maximumLifetime,
			minimumPasswordLength: this.minimumPasswordLength,
			/* Password Policy Enhancement Start */
			minUCasePassLength: this.minUCasePassLength,
			minLCasePassLength: this.minLCasePassLength,
			minNonAlphabetic: this.minNonAlphabetic,
			storeSite: this.storeSite,
			charOrder: this.charOrder,
			/* Password Policy Enhancement End */
			reusePassword: this.reusePassword,
			matchUserId: this.matchUserId
		});
	}
}
