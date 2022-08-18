# Commerce Password Policy Enhancement POC

## WARRANTY & SUPPORT 
HCL Software provides HCL Commerce open source assets “as-is” without obligation to support them nor warranties or any kind, either express or implied, including the warranty of title, non-infringement or non-interference, and the implied warranties and conditions of merchantability and fitness for a particular purpose. HCL Commerce open source assets are not covered under the HCL Commerce master license nor Support contracts.

If you have questions or encounter problems with an HCL Commerce open source asset, please open an issue in the asset's GitHub repository. For more information about [GitHub issues](https://docs.github.com/en/issues), including creating an issue, please refer to [GitHub Docs](https://docs.github.com/en). The HCL Commerce Innovation Factory Team, who develops HCL Commerce open source assets, monitors GitHub issues and will do their best to address them. 

## HCLC Password Policy Enhancement POC

Provide a feature to configure the new rules for password policy and same will be applicable for Administrators / Shoppers at the time registration / profile update.     This password policy is for extending the OOTB Password policy to support stricter character cases, numbers, and string patterns.

## V8 Implementation
Please refer `Readme.md` file under `V8` folder for V8 implementation.

## V9 Implementation
Please refer `Readme.md` file under `V9` folder for V9 implementation.

### Rules - Password tokens:  
* Uppercase characters of European languages (A through Z, with diacritic marks, Greek and Cyrillic characters)
* Lowercase characters of European languages (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters).
* Base 10 digits (0 through 9).
* Non-alphanumeric (special) characters
* Any Unicode character that is categorized as an alphabetic character but is not uppercase or lowercase. This includes Unicode characters from Asian languages. 

### In addition
* The password should not contain contextual information such as login credentials, website name etc
* The password should not have sequential characters like "abcd1234"
* The password should not have all same letters like "Aaaaaaaaa"


