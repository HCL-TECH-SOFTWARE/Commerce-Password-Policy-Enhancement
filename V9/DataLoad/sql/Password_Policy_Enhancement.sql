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

CREATE TABLE X_PLCYPASSWD ( 
	PLCYPASSWD_ID BIGINT NOT NULL,
	MINUCASEPASSWDLEN INTEGER DEFAULT 0,
	MINLCASEPASSWDLEN INTEGER DEFAULT 0,
	MINNONALPHABETIC INTEGER DEFAULT 0,
	CHARORDER INTEGER DEFAULT 0,
	STORESITE VARCHAR ( 512 ),
	FIELD1 INTEGER DEFAULT 0,
	FIELD2 INTEGER DEFAULT 0,
	FIELD3 INTEGER DEFAULT 0,
	FIELD4 VARCHAR ( 128 ),
	FIELD5 VARCHAR ( 254 ),
	OPTCOUNTER SMALLINT NOT NULL DEFAULT 0,
	CONSTRAINT X_PLCYPASSWD_PK PRIMARY KEY( PLCYPASSWD_ID ),
	CONSTRAINT X_PLCYPASSWD_FK FOREIGN KEY ( PLCYPASSWD_ID ) REFERENCES PLCYPASSWD( PLCYPASSWD_ID ) ON DELETE CASCADE 
);

UPDATE cmdreg SET CLASSNAME = 'com.hcl.commerce.security.commands.HCLExtAuthenticationPolicyCmdImpl' WHERE INTERFACENAME = 'com.ibm.commerce.security.commands.AuthenticationPolicyCmd';

-- Insert Custom Configuration for all existing Password Policy from PLCYPASSWD to X_PLCYPASSWD 
-- Sample Insert Statement: use <PLCYPASSWD_ID> from PLCYPASSWD table
INSERT INTO X_PLCYPASSWD (PLCYPASSWD_ID) VALUES (<PLCYPASSWD_ID>);

COMMIT;
