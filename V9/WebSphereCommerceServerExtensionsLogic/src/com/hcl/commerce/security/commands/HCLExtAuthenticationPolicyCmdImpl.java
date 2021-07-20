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
package com.hcl.commerce.security.commands;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.NoResultException;

import org.apache.commons.lang.StringUtils;

import com.hcl.commerce.passwordpolicy.objects.XPasswordPolicy;
import com.hcl.commerce.passwordpolicy.persistence.XPasswordPolicyDaoImpl;
import com.hcl.commerce.ras.ExtECMessage;
import com.ibm.commerce.command.CommandFactory;
import com.ibm.commerce.datatype.TypedProperty;
import com.ibm.commerce.exception.ECApplicationException;
import com.ibm.commerce.exception.ECException;
import com.ibm.commerce.exception.ECSystemException;
import com.ibm.commerce.exception.ExceptionHandler;
import com.ibm.commerce.foundation.internal.common.util.encryption.EncryptionFactory;
import com.ibm.commerce.foundation.persistence.EntityDao;
import com.ibm.commerce.member.syncbeans.SyncBeanUtil;
import com.ibm.commerce.member.syncbeans.commands.LDAPUserSyncCmd;
import com.ibm.commerce.persistence.JpaEntityAccessBeanCacheUtil;
import com.ibm.commerce.ras.ECMessage;
import com.ibm.commerce.ras.ECMessageHelper;
import com.ibm.commerce.ras.ECMessageLog;
import com.ibm.commerce.ras.ECTrace;
import com.ibm.commerce.security.commands.AuthenticationPolicyCmd;
import com.ibm.commerce.security.commands.AuthenticationPolicyCmdImpl;
import com.ibm.commerce.security.commands.VerifyCredentialsCmd;
import com.ibm.commerce.security.commands.helper.PasswordValidationHelper;
import com.ibm.commerce.security.commands.helper.UserPasswordHistory;
import com.ibm.commerce.security.commands.helper.UserPasswordHistoryEntry;
import com.ibm.commerce.security.keys.WCKeyRegistry;
import com.ibm.commerce.server.WcsApp;
import com.ibm.commerce.user.objects.PolicyAccountAccessBean;
import com.ibm.commerce.user.objects.PolicyPasswordAccessBean;
import com.ibm.commerce.user.objects.UserPasswordHistoryAccessBean;
import com.ibm.commerce.user.objects.UserRegistryAccessBean;
import com.ibm.icu.lang.UCharacter;
import com.ibm.icu.text.UTF16;



public class HCLExtAuthenticationPolicyCmdImpl extends AuthenticationPolicyCmdImpl implements AuthenticationPolicyCmd{
	
	 public static final String COPYRIGHT = "(c) Copyright International Business Machines Corporation 1996,2008";
	    private String istrLogonId;
	    private String istrPassword;
	    private int inCheckNumberOfPreviousPasswords;
	    private boolean ibCheckUserIDDissimilar;
	    private int inMininumRequiredPasswordLength;
	    private int inMinimumRequiredLetters;
	    private int inMinimumRequiredDigits;
	    private int inAllowableConsecutiveCharacters;
	    private int inAllowableMaximumCharacters;
	    // custom code start
	    private int inMinimumUpperCaseLetters;
	    private int inMinimumLowerCaseLetters;
	    private int inMinimumSpecialCharacters;
	    private int isCharactersOrderCheck;
	    private String siteName;
	    private int inUCaseCount;
	    private int inLCaseCount;
	    private int inSpecialCharacterCount;
	    private boolean isExtPasswordPolicyAvl;
	    // custom code end
	    private int inLetterCount;
	    private int inDigitCount;
	    private int inConsecutiveCounter;
	    private int inMaximumOccurence;
	    private boolean ibPasswordCompliant;
	    private String istrDefinedAccountPolicy;
	    private String actualSiteName;
	    public static String ERRTASK_NAME;
	    
	    static {
	        AuthenticationPolicyCmdImpl.ERRTASK_NAME = "AuthenticationPolicyErrorView";
	    }
	    
	    public HCLExtAuthenticationPolicyCmdImpl() {
	        this.istrLogonId = null;
	        this.istrPassword = null;
	        this.inCheckNumberOfPreviousPasswords = 4;
	        this.ibCheckUserIDDissimilar = false;
	        this.inMininumRequiredPasswordLength = -1;
	        this.inMinimumRequiredLetters = -1;
	        this.inMinimumRequiredDigits = -1;
	        this.inAllowableConsecutiveCharacters = -1;
	        this.inAllowableMaximumCharacters = -1;
	        this.inLetterCount = 0;
	        this.inDigitCount = 0;
	        // custom code start
	        this.inMinimumUpperCaseLetters = -1;
	        this.inMinimumLowerCaseLetters = -1; 
	        this.inMinimumSpecialCharacters = -1;
	        this.isCharactersOrderCheck = -1;
	        this.inUCaseCount = 0;
	        this.inLCaseCount = 0;
	        this.inSpecialCharacterCount = 0;
	        // custom code end
	        this.inConsecutiveCounter = 0;
	        this.inMaximumOccurence = 0;
	        this.ibPasswordCompliant = false;
	        this.istrDefinedAccountPolicy = null;
	    }
	    
	    protected void analyzePassword() {
	        final String strMethodName = "analyzePassword";
	        ECTrace.entry(4L, this.getClass().getName(), "analyzePassword");
	        final String strPassword = this.getPassword();
	        final int inPasswordLength = strPassword.length();
	        final ArrayList alPasswordElements = new ArrayList(inPasswordLength);
	        int cp;
	        for (int pos = 0; pos < inPasswordLength; pos += UTF16.getCharCount(cp)) {
	            cp = UTF16.charAt(strPassword, pos);
	            alPasswordElements.add(new Integer(cp));
	        }
	        Collections.sort((List<Comparable>)alPasswordElements);
	        int nCurrentConsecutiveCounter = 0;
	        int nCurrentMaximumCounter = 0;
	        int chConsecutiveCurrent = 0;
	        int chConsecutivePrevious = 0;
	        Integer chMaxCurrent = null;
	        Integer chMaxPrevious = null;
	        for (int pos = 0, arraycount = 0; pos < inPasswordLength; pos += UTF16.getCharCount(chConsecutiveCurrent), ++arraycount) {
	            chConsecutiveCurrent = UTF16.charAt(strPassword, pos);
	            chMaxCurrent = (Integer) alPasswordElements.get(arraycount);
	            //custom code start
	            if(!UCharacter.isDigit(chConsecutiveCurrent) && !UCharacter.isLetter(chConsecutiveCurrent) && !UCharacter.isWhitespace(chConsecutiveCurrent)) {
	            	++this.inSpecialCharacterCount;
	            }//custom code end	
	            else if (UCharacter.isDigit(chConsecutiveCurrent)) {
	                ++this.inDigitCount;
	            }
	            else if (UCharacter.isLetter(chConsecutiveCurrent)) {
	                ++this.inLetterCount;
	                //custom code start
	                if(UCharacter.isUpperCase(chConsecutiveCurrent)) {
	                	++this.inUCaseCount;
	                }
	                if(UCharacter.isLowerCase(chConsecutiveCurrent)) {
	                	++this.inLCaseCount;
	                }
	                //custom code end
	            }
	            if (chConsecutiveCurrent == chConsecutivePrevious) {
	                if (++nCurrentConsecutiveCounter > this.inConsecutiveCounter) {
	                    this.inConsecutiveCounter = nCurrentConsecutiveCounter;
	                }
	            }
	            else {
	                nCurrentConsecutiveCounter = 1;
	            }
	            chConsecutivePrevious = chConsecutiveCurrent;
	            if (chMaxPrevious != null && chMaxCurrent.equals(chMaxPrevious)) {
	                if (++nCurrentMaximumCounter > this.inMaximumOccurence) {
	                    this.inMaximumOccurence = nCurrentMaximumCounter;
	                }
	            }
	            else {
	                nCurrentMaximumCounter = 1;
	            }
	            chMaxPrevious = chMaxCurrent;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "analyzePassword");
	    }
	    
	    protected String getLogonId() {
	        return this.istrLogonId;
	    }
	    
	    protected String getPassword() {
	        return this.istrPassword;
	    }
	    
	    public boolean isPasswordCompliant() {
	        return this.ibPasswordCompliant;
	    }
	    
	    // Custom code start
	    
	    public String getActualSiteName() {
			return actualSiteName;
		}

		public void setActualSiteName(String actualSiteName) {
			this.actualSiteName = actualSiteName;
		}

	    // Custom code start
		
		protected boolean isPreviousPasswordDifferent() {
	        final String strMethodName = "isPreviousPasswordDifferent";
	        ECTrace.entry(4L, this.getClass().getName(), "isPreviousPasswordDifferent");
	        boolean bResult = false;
	        ECTrace.trace(4L, this.getClass().getName(), "isPreviousPasswordDifferent", "The number of previous passwords to be checked is " + this.inCheckNumberOfPreviousPasswords);
	        Label_0733: {
	            if (this.inCheckNumberOfPreviousPasswords >= 0) {
	                boolean bValidCredentials = false;
	                boolean bExistingUser = true;
	                UserRegistryAccessBean abUserReg = null;
	                try {
	                    abUserReg = ((UserRegistryAccessBean)JpaEntityAccessBeanCacheUtil.newJpaEntityAccessBean((Class)UserRegistryAccessBean.class)).findByUserLogonId(this.getLogonId());
	                }
	                catch (Exception ex3) {
	                    bResult = true;
	                    bExistingUser = false;
	                }
	                if (!bExistingUser) {
	                    break Label_0733;
	                }
	                try {
	                    final VerifyCredentialsCmd cmdVerifyCredentials = (VerifyCredentialsCmd)CommandFactory.createCommand("com.ibm.commerce.security.commands.VerifyCredentialsCmd", this.commandContext.getStoreId());
	                    cmdVerifyCredentials.setLogonId(this.getLogonId());
	                    cmdVerifyCredentials.setPassword(this.getPassword());
	                    cmdVerifyCredentials.setCommandContext(this.commandContext);
	                    cmdVerifyCredentials.execute();
	                    bValidCredentials = cmdVerifyCredentials.isValidCredentials();
	                    bResult = !bValidCredentials;
	                    ECTrace.trace(4L, this.getClass().getName(), "isPreviousPasswordDifferent", "Result after checking against the password stored in the USERREG table " + bResult);
	                }
	                catch (ECException expCmd) {
	                    ECTrace.trace(4L, this.getClass().getName(), "isPreviousPasswordDifferent", "Return true and caught an ECException: " + ExceptionHandler.convertStackTraceToString((Throwable)expCmd));
	                    bResult = true;
	                }
	                if (!bResult || this.inCheckNumberOfPreviousPasswords <= 1) {
	                    break Label_0733;
	                }
	                final HashMap newHashedPwdMap = new HashMap();
	                try {
	                    int numOfPrevPasswordsToCheck = this.inCheckNumberOfPreviousPasswords - 1;
	                    ECTrace.trace(4L, this.getClass().getName(), "isPreviousPasswordDifferent", "Maximum number of passwords stored in the USERPWDHIST table " + numOfPrevPasswordsToCheck);
	                    final UserPasswordHistory userPwdHist = new UserPasswordHistory(abUserReg.getUserIdInEntityType());
	                    userPwdHist.initPreviousPasswords();
	                    UserPasswordHistoryEntry record = null;
	                    Block_21: {
	                        while (userPwdHist.hasPrevious()) {
	                            if (numOfPrevPasswordsToCheck <= 0) {
	                                break;
	                            }
	                            record = userPwdHist.previous();
	                            String newHashedPwd = null;
	                            newHashedPwd = (String) newHashedPwdMap.get(record.getSalt());
	                            if (newHashedPwd == null) {
	                                if (PasswordValidationHelper.isPasswordOneWayHashed()) {
	                                    newHashedPwd = PasswordValidationHelper.generateOneWayHashedPasswordWithoutEncryption(this.getPassword(), record.getSalt());
	                                }
	                                else {
	                                    newHashedPwd = this.getPassword();
	                                }
	                                newHashedPwdMap.put(record.getSalt(), newHashedPwd);
	                            }
	                            String strOriginDecryptedPassword = null;
	                            strOriginDecryptedPassword = PasswordValidationHelper.reverseEncryptedPassword(record.getPrevLogonPassword());
	                            if (newHashedPwd.equals(strOriginDecryptedPassword)) {
	                                bResult = false;
	                            }
	                            else if (PasswordValidationHelper.isPasswordOneWayHashed() && PasswordValidationHelper.isMultiHashAlgorithmEnabled()) {
	                                final boolean updatePassword = PasswordValidationHelper.isPasswordUpdateForMultiHashAlgorithmsRequiredForDecryptedPasswords(strOriginDecryptedPassword, this.getPassword(), record.getSalt());
	                                if (updatePassword) {
	                                    bResult = false;
	                                    byte[] newEncryptedPwd = null;
	                                    if (WCKeyRegistry.getInstance().isEncryptionKeyVersioningEnabled()) {
	                                        final String strVersion = PasswordValidationHelper.getVersionSuffix(record.getPrevLogonPassword());
	                                        if (PasswordValidationHelper.isPasswordOneWayHashed()) {
	                                            newEncryptedPwd = PasswordValidationHelper.generateOneWayHashedPassword(this.getPassword(), record.getSalt(), strVersion);
	                                        }
	                                        else {
	                                            newEncryptedPwd = EncryptionFactory.getInstance().getProvider("ActiveProvider").encrypt(this.getPassword(), (String)null, strVersion).getBytes();
	                                        }
	                                    }
	                                    final Long id = record.getUserPasswordHistoryId();
	                                    final UserPasswordHistoryAccessBean userPWH = new UserPasswordHistoryAccessBean();
	                                    userPWH.setInitKey_userPasswordHistoryId(id);
	                                    userPWH.instantiateEntity();
	                                    userPWH.setPreviousLogonPassword(newEncryptedPwd);
	                                }
	                            }
	                            if (!bResult) {
	                                break Block_21;
	                            }
	                            --numOfPrevPasswordsToCheck;
	                        }
	                        break Label_0733;
	                    }
	                    ECTrace.trace(4L, this.getClass().getName(), "isPreviousPasswordDifferent", "The previous password with USERPWDHST_ID " + record.getUserPasswordHistoryId() + " is the same as the new password.");
	                    break Label_0733;
	                }
	                catch (ECException ex) {
	                    ECTrace.exit(4L, this.getClass().getName(), "isPreviousPasswordDifferent");
	                    throw new RuntimeException((Throwable)ex);
	                }
	                catch (NoResultException ex2) {
	                    final ECSystemException expTmp = new ECSystemException(ECMessage._ERR_FINDER_EXCEPTION, this.getClass().getName(), "isPreviousPasswordDifferent", ECMessageHelper.generateMsgParms((Object)ex2.toString()), (Throwable)ex2);
	                    ECTrace.exit(4L, this.getClass().getName(), "isPreviousPasswordDifferent");
	                    throw new RuntimeException((Throwable)expTmp);
	                }
	            }
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isPreviousPasswordDifferent", (Object)new Boolean(bResult));
	        return bResult;
	    }
	    
	    protected boolean isUserIDDissimilar() {
	        final String strMethodName = "isUserIDDissimilar";
	        ECTrace.entry(4L, this.getClass().getName(), "isUserIDDissimilar");
	        boolean bResult = false;
	        if (this.ibCheckUserIDDissimilar) {
	            if (this.getLogonId().compareTo(this.getPassword()) != 0) {
	                bResult = true;
	            }
	        }
	        else {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isUserIDDissimilar");
	        return bResult;
	    }
	    
	    protected boolean isValidConsecutiveCharacters() {
	        final String strMethodName = "isValidConsecutiveCharacters";
	        ECTrace.entry(4L, this.getClass().getName(), "isValidConsecutiveCharacters");
	        boolean bResult = false;
	        if (this.inConsecutiveCounter <= this.inAllowableConsecutiveCharacters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isValidConsecutiveCharacters");
	        return bResult;
	    }
	    
	    protected boolean isValidMaximumCharacters() {
	        final String strMethodName = "isValidMaximumCharacters";
	        ECTrace.entry(4L, this.getClass().getName(), "isValidMaximumCharacters");
	        boolean bResult = false;
	        if (this.inMaximumOccurence <= this.inAllowableMaximumCharacters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isValidMaximumCharacters");
	        return bResult;
	    }
	    
	    protected boolean isValidMinimumDigits() {
	        final String strMethodName = "isValidMinimumDigits";
	        ECTrace.entry(4L, this.getClass().getName(), "isValidMinimumDigits");
	        boolean bResult = false;
	        if (this.inDigitCount >= this.inMinimumRequiredDigits) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isValidMinimumDigits");
	        return bResult;
	    }
	    
	    protected boolean isValidMinimumLength() {
	        final String strMethodName = "isValidMinimumLength";
	        ECTrace.entry(4L, this.getClass().getName(), "isValidMinimumLength");
	        boolean bResult = false;
	        if (this.getPassword().length() >= this.inMininumRequiredPasswordLength) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isValidMinimumLength");
	        return bResult;
	    }
	    
	    protected boolean isValidMinimumLetters() {
	        final String strMethodName = "isValidMinimumAlphabeticCharacters";
	        ECTrace.entry(4L, this.getClass().getName(), "isValidMinimumAlphabeticCharacters");
	        boolean bResult = false;
	        if (this.inLetterCount >= this.inMinimumRequiredLetters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "isValidMinimumAlphabeticCharacters");
	        return bResult;
	    }
	    
	    // custom code start
	    
	    protected boolean isValidMinimumUpperCaseLetters() {
	       
			/*
			 * // custom code start 
			 * this.inMinimumUpperCaseLetters = -1;
			 * this.inMinimumLowerCaseLetters = -1; 
			 * this.inMinimumSpecialCharacters = -1;
			 * this.isCharactersOrderCheck = -1; 
			 * this.inUCaseCount = 0; 
			 * this.inLCaseCount = 0;
			 * this.inSpecialCharacterCount = 0; 
			 * // custom code end
			 */	    	
	    	
	    	
	    	final String strMethodName = "isValidMinimumUpperCaseLetters";
	        ECTrace.entry(4L, this.getClass().getName(), strMethodName);
	        boolean bResult = false;
	        if (this.inUCaseCount >= this.inMinimumUpperCaseLetters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), strMethodName);
	        return bResult;
	    }
	    
	    protected boolean isValidMinimumLowerCaseLetters() {
		       
			/*
			 * // custom code start 
			 * this.inMinimumUpperCaseLetters = -1;
			 * this.inMinimumLowerCaseLetters = -1; 
			 * this.inMinimumSpecialCharacters = -1;
			 * this.isCharactersOrderCheck = -1; 
			 * this.inUCaseCount = 0; 
			 * this.inLCaseCount = 0;
			 * this.inSpecialCharacterCount = 0; 
			 * // custom code end
			 */	    	
	    	
	    	
	    	final String strMethodName = "isValidMinimumLowerCaseLetters";
	        ECTrace.entry(4L, this.getClass().getName(), strMethodName);
	        boolean bResult = false;
	        if (this.inLCaseCount >= this.inMinimumLowerCaseLetters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), strMethodName);
	        return bResult;
	    }
	    
	    protected boolean isValidMinimumSpecialCharacters() {
		       
			/*
			 * // custom code start 
			 * this.inMinimumUpperCaseLetters = -1;
			 * this.inMinimumLowerCaseLetters = -1; 
			 * this.inMinimumSpecialCharacters = -1;
			 * this.isCharactersOrderCheck = -1; 
			 * this.inUCaseCount = 0; 
			 * this.inLCaseCount = 0;
			 * this.inSpecialCharacterCount = 0; 
			 * // custom code end
			 */	    	
	    	
	    	
	    	final String strMethodName = "isValidMinimumSpecialCharacters";
	        ECTrace.entry(4L, this.getClass().getName(), strMethodName);
	        boolean bResult = false;
	        if (this.inSpecialCharacterCount >= this.inMinimumSpecialCharacters) {
	            bResult = true;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), strMethodName);
	        return bResult;
	    }
	    
	    
	    protected boolean isPasswordConatinsSitename() {
		       
			/*
			 * // custom code start 
			 * this.inMinimumUpperCaseLetters = -1;
			 * this.inMinimumLowerCaseLetters = -1; 
			 * this.inMinimumSpecialCharacters = -1;
			 * this.isCharactersOrderCheck = -1; 
			 * this.inUCaseCount = 0; 
			 * this.inLCaseCount = 0;
			 * this.inSpecialCharacterCount = 0; 
			 * // custom code end
			 */	    	
	    	
	    	//1-aurora.com|11-Emerald
	    	final String strMethodName = "isPasswordConatinsSitename";
	        ECTrace.entry(4L, this.getClass().getName(), strMethodName);
	        boolean bResult = false;
	        String actualSiteName = "";
	        String storeSiteName = this.siteName;
			if(!StringUtils.isEmpty(storeSiteName)) {
				String[] sitNameArr = storeSiteName.split("[|]");
				for(String storeSite : sitNameArr) {
					String[] storeSiteArr = storeSite.split("[-]");
					if(storeSiteArr[0].equals(getStoreId().toString())) {
					actualSiteName = storeSiteArr[1];
					setActualSiteName(actualSiteName);
					}
				}
		        if (getActualSiteName() != null && getPassword().toLowerCase().contains(getActualSiteName().toLowerCase())) {
		            bResult = true;
		        }
			}

	        ECTrace.exit(4L, this.getClass().getName(), strMethodName);
	        return bResult;
	    }
	    
	    protected boolean isPasswordCharInOrders() {
		       
			/*
			 * // custom code start 
			 * this.inMinimumUpperCaseLetters = -1;
			 * this.inMinimumLowerCaseLetters = -1; 
			 * this.inMinimumSpecialCharacters = -1;
			 * this.isCharactersOrderCheck = -1; 
			 * this.inUCaseCount = 0; 
			 * this.inLCaseCount = 0;
			 * this.inSpecialCharacterCount = 0; 
			 * // custom code end
			 */	    	
	    	
	    	
	    	final String strMethodName = "isPasswordCharInOrders";
	        ECTrace.entry(4L, this.getClass().getName(), strMethodName);
	        boolean bResult = false;
	        if (this.isCharactersOrderCheck == 1) {
	         String numberRegex = "([-?0-9]{4,})";
	   		 String stringRgex = "([-?a-z]{4,})";
	   		 String str =  getPassword();
	   		 bResult = checkLetterOrder(stringRgex, str);
	   		 if(bResult)
	   			 return bResult;
	   		bResult = checkLetterOrder(numberRegex, str);
	        }
	        ECTrace.exit(4L, this.getClass().getName(), strMethodName);
	        return bResult;
	    }
	    
		protected boolean checkLetterOrder(String regex, String inputStr) {
			final String strMethodName = "checkLetterOrder";
			ECTrace.entry(4L, this.getClass().getName(), strMethodName);
			Pattern pattern  = null;
			boolean isLetterInOrder = false;
			 pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE); 
			  Matcher matcher = pattern.matcher(inputStr); 
			  while(matcher.find())
			  {
				  String matchFound = matcher.group();
				  isLetterInOrder = isLetterInOrder(matchFound);
				  if(isLetterInOrder) {
					  break;
				  }
			  }
			  ECTrace.exit(4L, this.getClass().getName(), strMethodName);
			  return isLetterInOrder;
		}
		
		protected boolean isLetterInOrder(String s) {
			final String strMethodName = "checkLetterOrder";
			ECTrace.entry(4L, this.getClass().getName(), strMethodName);
		        // create a character array the same length as the string
		        char c[] = new char [s.length()];
		       
		        // assign the string to character array
		        c = s.toCharArray();	     
		        // sort character array
		        Arrays.sort(c);

		        // check if character array and string are equal 
		        for (int i = 0; i < s.length(); i++)
		            if (c[i] != s.charAt(i)) 
		                return false;
		        ECTrace.exit(4L, this.getClass().getName(), strMethodName);       
		        return true;    
		    }
	    
	    //custom code end
	    
	    
	    protected boolean loadUserPasswordPolicy() throws ECException {
	        final String strMethodName = "loadUserPasswordPolicy";
	        ECTrace.entry(4L, this.getClass().getName(), "loadUserPasswordPolicy");
	        try {
	            String strPolicyAcctId = null;
	            if (this.istrDefinedAccountPolicy != null) {
	                strPolicyAcctId = this.istrDefinedAccountPolicy;
	            }
	            else {
	                final String strLogonId = this.getLogonId();
	                final UserRegistryAccessBean abUserReg = ((UserRegistryAccessBean)JpaEntityAccessBeanCacheUtil.newJpaEntityAccessBean((Class)UserRegistryAccessBean.class)).findByUserLogonId(strLogonId);
	                strPolicyAcctId = abUserReg.getPolicyAccountId();
	            }
	            if (strPolicyAcctId == null || strPolicyAcctId.trim().length() == 0) {
	                this.ibPasswordCompliant = true;
	                ECTrace.trace(4L, this.getClass().getName(), "loadUserPasswordPolicy", "The user does not have a password policy");
	                ECTrace.exit(4L, this.getClass().getName(), "loadUserPasswordPolicy");
	                return false;
	            }
	            final PolicyAccountAccessBean abPolicyAccount = (PolicyAccountAccessBean)JpaEntityAccessBeanCacheUtil.newJpaEntityAccessBean((Class)PolicyAccountAccessBean.class);
	            abPolicyAccount.setInitKey_iPolicyAccountId(strPolicyAcctId);
	            abPolicyAccount.instantiateEntity();
	            final String strPolicyPasswordId = abPolicyAccount.getPolicyPasswordId();
	            final PolicyPasswordAccessBean abPolicyPassword = (PolicyPasswordAccessBean)JpaEntityAccessBeanCacheUtil.newJpaEntityAccessBean((Class)PolicyPasswordAccessBean.class);
	            abPolicyPassword.setInitKey_iPolicyPasswordId(strPolicyPasswordId);
	            abPolicyPassword.instantiateEntity();
	            this.inCheckNumberOfPreviousPasswords = -abPolicyPassword.getReusePasswordInEntityType();
	            this.ibCheckUserIDDissimilar = (abPolicyPassword.getMatchUserIdInEntityType() == 0);
	            this.inMininumRequiredPasswordLength = abPolicyPassword.getMinimumPasswordLengthInEntityType();
	            this.inMinimumRequiredLetters = abPolicyPassword.getMinimumAlphabeticInEntityType();
	            this.inMinimumRequiredDigits = abPolicyPassword.getMinimumNumericInEntityType();
	            this.inAllowableConsecutiveCharacters = abPolicyPassword.getMaximumConsecutiveTypeInEntityType();
	            this.inAllowableMaximumCharacters = abPolicyPassword.getMaximumInstancesInEntityType();
	            
	            // custom code start
		        
		        // load password policy from extension tables X_PLCYPASSWD 
	            this.isExtPasswordPolicyAvl = false;
		        EntityDao<XPasswordPolicy, Long> xPasswordPolicyDao = new XPasswordPolicyDaoImpl();
				List<XPasswordPolicy> xPasswordPolicies = xPasswordPolicyDao.query("XPasswordPolicy.findById", new Long(strPolicyPasswordId));
				if(xPasswordPolicies != null && xPasswordPolicies.size() > 0) {
					this.isExtPasswordPolicyAvl = true;
					for (XPasswordPolicy xPasswordPolicy : xPasswordPolicies) {
						this.inMinimumUpperCaseLetters = xPasswordPolicy.getMinUCasePassLength();
				        this.inMinimumLowerCaseLetters = xPasswordPolicy.getMinLCasePassLength(); 
				        this.inMinimumSpecialCharacters = xPasswordPolicy.getMinNonAlphabetic();
				        this.isCharactersOrderCheck = xPasswordPolicy.getCharOrder();
				        this.siteName = xPasswordPolicy.getStoreSite();
					}
				}
		        
		        // custom code end
	        }
	        catch (NoResultException ex) {
	            final ECSystemException expTmp = new ECSystemException(ECMessage._ERR_FINDER_EXCEPTION, this.getClass().getName(), "loadUserPasswordPolicy", ECMessageHelper.generateMsgParms((Object)ex.toString()), (Throwable)ex);
	            ECTrace.exit(4L, this.getClass().getName(), "loadUserPasswordPolicy");
	            throw expTmp;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "loadUserPasswordPolicy");
	        return true;
	    }
	    
	    public void performExecute() throws ECException {
	        final String strMethodName = "performExecute";
	        ECTrace.entry(4L, this.getClass().getName(), "performExecute");
	        final String strPasswordPolicyEnabled = WcsApp.configProperties.getValue("Security/passwordpolicy");
	        if (strPasswordPolicyEnabled != null && "true".equalsIgnoreCase(strPasswordPolicyEnabled)) {
	            boolean bLDAPEnabled = false;
	            final String strAuthMode = WcsApp.configProperties.getValue("MemberSubSystem/AuthenticationMode");
	            if (strAuthMode != null && strAuthMode.equalsIgnoreCase("LDAP")) {
	                try {
	                    String astrUserIdentifier = this.istrLogonId;
	                    if (!SyncBeanUtil.isUserDN(astrUserIdentifier)) {
	                        try {
	                            final UserRegistryAccessBean abUserRegistry = ((UserRegistryAccessBean)JpaEntityAccessBeanCacheUtil.newJpaEntityAccessBean((Class)UserRegistryAccessBean.class)).findByUserLogonId(this.istrLogonId);
	                            astrUserIdentifier = abUserRegistry.getUserId();
	                        }
	                        catch (NoResultException oe) {
	                            ECTrace.trace(4L, this.getClass().getName(), "performExecute", "Can not find this user in WCS User Cache by logon id " + astrUserIdentifier + " , exception happens: " + ExceptionHandler.convertStackTraceToString((Throwable)oe) + " , will treat this user as LDAP user.");
	                            bLDAPEnabled = true;
	                        }
	                    }
	                    final LDAPUserSyncCmd cmdLDAPSync = (LDAPUserSyncCmd)CommandFactory.createCommand(LDAPUserSyncCmd.NAME, new Integer(0));
	                    if (!cmdLDAPSync.isExcludedUser(astrUserIdentifier)) {
	                        ECTrace.trace(4L, this.getClass().getName(), "performExecute", "This user is in LDAP");
	                        bLDAPEnabled = true;
	                    }
	                }
	                catch (Exception ece) {
	                    ECMessageLog.out(ECMessage._ERR_GENERIC, this.getClass().getName(), "performExecute", (Object)ece.toString());
	                    ECTrace.trace(4L, this.getClass().getName(), "performExecute", "Excepiton happen when checking if this user is excluded or not: " + ExceptionHandler.convertStackTraceToString((Throwable)ece));
	                }
	            }
	            if (!bLDAPEnabled) {
	                super.performExecute();
	                if (this.loadUserPasswordPolicy()) {
	                    this.validatePasswordCompliance();
	                }
	            }
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "performExecute");
	    }
	    
	    public void setAccountPolicy(final String strDefinedAccountPolicy) {
	        if (strDefinedAccountPolicy != null && strDefinedAccountPolicy.length() > 0) {
	            this.istrDefinedAccountPolicy = strDefinedAccountPolicy.trim();
	        }
	    }
	    
	    public void setErrorTask(final String strErrorTask) {
	        if (strErrorTask != null && strErrorTask.trim().length() != 0) {
	            AuthenticationPolicyCmdImpl.ERRTASK_NAME = strErrorTask.trim();
	        }
	    }
	    
	    public void setLogonId(final String strLogonId) {
	        if (strLogonId != null && strLogonId.trim().length() != 0) {
	            this.istrLogonId = strLogonId.trim();
	        }
	    }
	    
	    public void setPassword(final String strPassword) {
	        if (strPassword != null && strPassword.trim().length() != 0) {
	            this.istrPassword = strPassword.trim();
	        }
	    }
	    
	    public void validateParameters() throws ECException {
	        final String strMethodName = "validateParameters";
	        ECTrace.entry(4L, this.getClass().getName(), "validateParameters");
	        if (this.getLogonId() == null || this.getLogonId().trim().length() == 0) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2000");
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_MISSING_PARMS, this.getClass().getName(), "validateParameters", ECMessageHelper.generateMsgParms((Object)"2000"), AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validateParameters");
	            throw expTmp;
	        }
	        if (this.getPassword() == null || this.getPassword().trim().length() == 0) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2020");
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_MISSING_PARMS, this.getClass().getName(), "validateParameters", ECMessageHelper.generateMsgParms((Object)"2020"), AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validateParameters");
	            throw expTmp;
	        }
	        ECTrace.exit(4L, this.getClass().getName(), "validateParameters");
	    }
	    
	    protected void validatePasswordCompliance() throws ECApplicationException {
	        final String strMethodName = "validatePasswordCompliance";
	        ECTrace.entry(4L, this.getClass().getName(), "validatePasswordCompliance");
	        this.analyzePassword();
	        if (!this.isValidMinimumLength()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2200");
	            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMininumRequiredPasswordLength), (Object)new Integer(this.inMinimumRequiredDigits), (Object)new Integer(this.inMinimumRequiredLetters));
	            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_MINIMUMLENGTH_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp;
	        }
	        if (!this.isPreviousPasswordDifferent()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2260");
	            final ECApplicationException expTmp2 = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_REUSEOLD_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp2;
	        }
	        if (!this.isUserIDDissimilar()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2250");
	            final ECApplicationException expTmp2 = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_USERIDMATCH_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp2;
	        }
	        if (!this.isValidConsecutiveCharacters()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2210");
	            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inAllowableConsecutiveCharacters));
	            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_MAXCONSECUTIVECHAR_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp;
	        }
	        if (!this.isValidMaximumCharacters()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2220");
	            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inAllowableMaximumCharacters));
	            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_MAXINTANCECHAR_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp;
	        }
	        if (!this.isValidMinimumLetters()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2230");
	            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMinimumRequiredLetters), (Object)new Integer(this.inMininumRequiredPasswordLength), (Object)new Integer(this.inMinimumRequiredDigits));
	            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_MINIMUMLETTERS_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp;
	        }
	        if (!this.isValidMinimumDigits()) {
	            final TypedProperty hshNVPs = new TypedProperty();
	            hshNVPs.put((Object)"ErrorCode", (Object)"2240");
	            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMinimumRequiredDigits), (Object)new Integer(this.inMininumRequiredPasswordLength), (Object)new Integer(this.inMinimumRequiredLetters));
	            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
	            final ECApplicationException expTmp = new ECApplicationException(ECMessage._ERR_AUTHENTICATION_MINIMUMDIGITS_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
	            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	            throw expTmp;
	        }
	        // custom code start
	        if(this.isExtPasswordPolicyAvl) {
		        if (!this.isValidMinimumUpperCaseLetters()) {
		            final TypedProperty hshNVPs = new TypedProperty();
		            hshNVPs.put((Object)"ErrorCode", (Object)"2270");
		            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMinimumUpperCaseLetters), (Object)new Integer(this.inMinimumLowerCaseLetters), (Object)new Integer(this.inMinimumSpecialCharacters));
		            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
		            final ECApplicationException expTmp = new ECApplicationException(ExtECMessage._ERR_AUTHENTICATION_MINIMUMUPPERCHAR_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
		            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
		            throw expTmp;
		        }
		        if (!this.isValidMinimumLowerCaseLetters()) {
		            final TypedProperty hshNVPs = new TypedProperty();
		            hshNVPs.put((Object)"ErrorCode", (Object)"2280");
		            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMinimumLowerCaseLetters), (Object)new Integer(this.inMinimumUpperCaseLetters), (Object)new Integer(this.inMinimumSpecialCharacters));
		            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
		            final ECApplicationException expTmp = new ECApplicationException(ExtECMessage._ERR_AUTHENTICATION_MINIMUMLOWERCHAR_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
		            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
		            throw expTmp;
		        }
		        if (!this.isValidMinimumSpecialCharacters()) {
		            final TypedProperty hshNVPs = new TypedProperty();
		            hshNVPs.put((Object)"ErrorCode", (Object)"2290");
		            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(this.inMinimumSpecialCharacters), (Object)new Integer(this.inMinimumUpperCaseLetters), (Object)new Integer(this.inMinimumLowerCaseLetters));
		            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
		            final ECApplicationException expTmp = new ECApplicationException(ExtECMessage._ERR_AUTHENTICATION_MINIMUMSPECIALCHAR_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
		            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
		            throw expTmp;
		        }
		        if (this.isPasswordConatinsSitename()) {
		            final TypedProperty hshNVPs = new TypedProperty();
		            hshNVPs.put((Object)"ErrorCode", (Object)"2300");
		            final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)getActualSiteName());
		            hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
		            final ECApplicationException expTmp = new ECApplicationException(ExtECMessage._ERR_AUTHENTICATION_SITEMATCH_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", msgParams, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
		            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
		            throw expTmp;
		        }
		        if (this.isPasswordCharInOrders()) {
		            final TypedProperty hshNVPs = new TypedProperty();
		            hshNVPs.put((Object)"ErrorCode", (Object)"2310");
		            //final Object[] msgParams = ECMessageHelper.generateMsgParms((Object)new Integer(getActualSiteName()));
		            //hshNVPs.put((Object)"excMsgParm", (Object)msgParams);
		            final ECApplicationException expTmp = new ECApplicationException(ExtECMessage._ERR_AUTHENTICATION_LETTERSINORDER_PASSWORD, this.getClass().getName(), "validatePasswordCompliance", null, AuthenticationPolicyCmdImpl.ERRTASK_NAME, hshNVPs);
		            ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
		            throw expTmp;
		        }
	        }
	        // custom code end
	        this.ibPasswordCompliant = true;
	        ECTrace.exit(4L, this.getClass().getName(), "validatePasswordCompliance");
	    }

} 
