# About the Commerce Password Policy Enhancement POC

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


