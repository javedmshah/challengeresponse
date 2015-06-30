/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

/*
 * author Javed Shah
 * 
 */

package org.forgerock.openam.authentication.modules.challengeresponse;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.shared.debug.Debug;
import com.iplanet.sso.SSOException;
import com.sun.identity.shared.datastruct.CollectionHelper;

import javax.servlet.http.HttpServletRequest;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.authentication.spi.AuthLoginException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;


public class ChallengeResponseModule extends AMLoginModule {

    private static final String AUTH_MODULE_NAME = "amAuthChallengeResponse";
    
    private static final Debug debug = Debug.getInstance(AUTH_MODULE_NAME);
    // orders defined in the callbacks file
    private String userResponse;
    private HttpServletRequest httpRequestObj = null;
    private String userName;
    private String attributeName;
    private boolean hashEnabled;
    private String question;
    private Map options;
    private ResourceBundle bundle;
    // Name of the resource bundle
    private final static String amAuthChallengeResponse = "amAuthChallengeResponse";
    private static final String AUTHLEVEL = "iplanet-am-auth-challengeresponse-auth-level";
    private static final String ATTR_NAME = "iplanet-am-auth-challengeresponse-attribute-name";
    private static final String HASH_ENABLED = "iplanet-am-auth-challengeresponse-hash-enabled";
    private static final String CHALLENGE_QUESTION_1 = "iplanet-am-auth-challengeresponse-question-1";
    /**
     * Constructs an instance of the ChallengeResponseModule.
     */
    public ChallengeResponseModule() {
    	super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
    	String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL);

        if (authLevel != null) {
            try {
                setAuthLevel(Integer.parseInt(authLevel));
            } catch (Exception e) {
                debug.error("Unable to set auth level " + authLevel, e);
            }
        }
        try {
            userName = (String) sharedState.get(getUserKey());
        } catch (Exception e) {
            debug.error("Adaptive.init() : " + "Unable to set userName : ", e);
        }
    	this.options = options;
    	initParams();
    	
    	System.out.println("\n\n username -> "+userName);
        System.out.println("\n\n sharedState -> "+sharedState);
        System.out.println("\n\n options -> "+options);
        
        bundle = amCache.getResBundle(amAuthChallengeResponse, getLoginLocale());
    }
    
    private void initParams() {
    	attributeName = getOption(options, ATTR_NAME);
    	System.out.println("\n\n attr -> "+attributeName);
    	hashEnabled = getOptionAsBoolean(options, HASH_ENABLED);
    	System.out.println("\n\n hash -> "+hashEnabled);
    	question = getOption(options, CHALLENGE_QUESTION_1);
    	System.out.println("\n\n q -> "+question);
    }
    protected String getOption(Map m, String i) {
    	return CollectionHelper.getMapAttr(m, i);
    }
    protected boolean getOptionAsBoolean(Map m, String i) {
        String s = null;
        s = CollectionHelper.getMapAttr(m, i);
        return Boolean.parseBoolean(s);
    }

    protected int getOptionAsInteger(Map m, String i) {
        String s = null;
        int retVal = 0;

        s = CollectionHelper.getMapAttr(m, i);
        if (s != null) {
            retVal = Integer.parseInt(s);
        }
        return retVal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
    	
    	System.out.println("INSIDE process of ChallengeResponseModule, state: "+state);
    			
    	if (debug.messageEnabled()) {
    		debug.message("ChallengeResponseModule::process state: " + state);
        }
    	int nextState = ISAuthConstants.LOGIN_SUCCEED;
        switch (state) {
         case 3:
        	 System.out.println("state 4");
        	 // error condition, show page
        	 throw new AuthLoginException("Incorrect Challenge Response!");
         case 1:
        	 substituteUIStrings();
        	 //nextState = ISAuthConstants.LOGIN_SUCCEED;
        	 nextState = 2;
        	 break;
         case 2:
        	 System.out.println("state 2");
        	 javax.security.auth.callback.NameCallback response = (javax.security.auth.callback.NameCallback) callbacks[0];
        	 userResponse = new String(response.getName());
             // check the response against OpenDJ
    		 System.out.println("checking response : state 3: "+userResponse);
    		 Properties prop = new Properties();
				InputStream input = null;
				
				// default to error
				nextState = 3;
				
				System.out.println("ChallengeResponse:: properties: "+attributeName+", "+hashEnabled);
				AMIdentity amIdentity = getIdentity(userName);
		        
		        try {
		        	System.out.println("amIdentity: "+amIdentity.getAttributes());
			        Set<String> attr = (Set<String>) amIdentity.getAttribute(attributeName); 
			        Iterator<String> i = attr.iterator();
					// only expecting 1 value in the response attribute 
			        if (i.hasNext()) {
						try {
							String value = (String) i.next();
							System.out.println("value of attribute: "+value);
							// is value hashed?
							if(hashEnabled) {
								userResponse = computeSha1OfString(userResponse);
								System.out.println("value of hashed response: "+userResponse);
								if(value.equalsIgnoreCase(userResponse)) {
									nextState = ISAuthConstants.LOGIN_SUCCEED;
								}
							} else {
								if(value.equalsIgnoreCase(userResponse)) {
									nextState = ISAuthConstants.LOGIN_SUCCEED;
								}
							}
						} catch (Exception e) {
							System.out.println("Cannot parse json. " + e);
							throw new AuthLoginException("Cannot parse json..unable to read attribtue value using amIdentity");
						}
					} else {
						System.out.println("did not find attribute in user: "+attributeName+", "+amIdentity);
					}
		        } catch(com.sun.identity.idm.IdRepoException idrepo) {
		        	System.out.println("IdRepoException thrown " + idrepo);
					throw new AuthLoginException("IdRepoException thrown from ChallengeResponse module");
		        } catch(SSOException ssoe) {
		        	System.out.println("SSOException thrown " + ssoe);
					throw new AuthLoginException("SSOException thrown from ChallengeResponse module");
		        }
		        
                break;
             default:
                 throw new AuthLoginException("invalid state");
  
         }
         return nextState;
    }
    public String computeSha1OfString(final String message)
            throws UnsupportedOperationException, NullPointerException {
        try {
            return computeSha1OfByteArray(message.getBytes(("UTF-8")));
        }
        catch (UnsupportedEncodingException ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

    private String computeSha1OfByteArray(final byte[] message)
            throws UnsupportedOperationException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(message);
            byte[] res = md.digest();
            return toHexString(res);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException(ex);
        }
    }
    
    /**
     * Gets the user's AMIdentity from LDAP.
     *
     * @param userName The user's name.
     * @return The AMIdentity for the user.
     */
    public AMIdentity getIdentity(String userName) {
        AMIdentity amIdentity = null;
        AMIdentityRepository amIdRepo = getAMIdentityRepository(getRequestOrg());

        IdSearchControl idsc = new IdSearchControl();
        idsc.setAllReturnAttributes(true);
        Set<AMIdentity> results = Collections.EMPTY_SET;

        try {
            idsc.setMaxResults(0);
            IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.USER, userName, idsc);
            if (searchResults != null) {
                results = searchResults.getSearchResults();
                System.out.println("results: "+results);
            }

            if (results.isEmpty()) {
                throw new IdRepoException("getIdentity : User " + userName
                        + " is not found");
            } else if (results.size() > 1) {
                throw new IdRepoException(
                        "getIdentity : More than one user found for the userName "
                                + userName);
            }

            amIdentity = results.iterator().next();
        } catch (IdRepoException e) {
            debug.error("Error searching Identities with username : " + userName, e);
        } catch (SSOException e) {
            debug.error("Module exception : ", e);
        }

        return amIdentity;
    }

    public static String getAddressFromRequest(HttpServletRequest request) {
        String xfwdFor = request.getHeader("X-Forwarded-For");
        if (xfwdFor != null)
            return xfwdFor;
        return request.getRemoteAddr();
    }
    
    private String toHexString(byte[] bytes) {
        char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Principal getPrincipal() {
        return new ChallengeResponseModulePrincipal(userName);
    }
    private void substituteUIStrings() throws AuthLoginException
    {
        // Get service specific attribute configured in OpenAM
        System.out.println("question from config: "+question);

        Callback[] crquestion = getCallback(2);

        replaceCallback(2, 0, new NameCallback(question));
    }

}
