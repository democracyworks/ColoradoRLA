/*
 * Free & Fair Colorado RLA System
 * 
 * @title ColoradoRLA
 * @created Aug 27, 2017
 * @copyright 2017 Free & Fair
 * @license GNU General Public License 3.0
 * @author Joe Kiniry <kiniry@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.auth;

import org.apache.log4j.Logger;

import com.google.gson.Gson;

import spark.Request;
import spark.Response;

import us.freeandfair.corla.json.SubmittedCredentials;
import us.freeandfair.corla.model.Administrator;
import us.freeandfair.corla.model.Administrator.AdministratorType;
import us.freeandfair.corla.model.County;

/**
 * @description <description>
 * @explanation <explanation>
 * @bon OPTIONAL_BON_TYPENAME
 */
public interface AuthenticationInterface {
  /**
   * The constant for the "admin" attribute of the current session.
   */
  String ADMIN = "admin";
  
  /**
   * The constant for the "challenge" attribute of the current session.
   */
  String CHALLENGE = "challenge";
  
  /**
   * The constant for the "username" request parameter.
   */
  String USERNAME = "username";
  
  /**
   * The constant for the "password" request parameter.
   */
  String PASSWORD = "password";
  
  /**
   * The constant for the "second factor" request parameter.
   */
  String SECOND_FACTOR = "second_factor";
  
  /**
   * The constant used to denote which authentication stage the session is in. 
   * The value of this attribute in a value of the `AuthenticationStage` 
   * enumeration.
   */
  String AUTH_STAGE = "authentication_stage";
  
  /**
   * Set the logger for the authentication subsystem.  This method should
   * be called immediately after construction and before the subsystem is used.
   * @param the_logger the logger to use.
   */
  void setLogger(Logger the_logger);

  /**
   * Set the GSON serialization/deserialization subsystem to use. This method
   * should be called immediately after construction and before the subsystem
   * is used.
   * @param the_gson the GSON subsystem to use.
   */
  void setGSON(Gson the_gson);

  /**
   * Set the DNS name of the authentication server to use for this particular
   * authentication service. 
   * @param the_name the full DNS name of the authentication server.
   */
  void setAuthenticationServerName(String the_name);
  
  /**
   * Authenticate the administrator `the_username` with credentials
   * `the_password` (for traditional authentication) or `the_second_factor`
   * (for two-factor authentication).
   * @trace authentication.authenticate_county_administrator
   * @trace authentication.authenticate_state_administrator
   * @return true iff authentication succeeds.
   * @param the_request The request.
   * @param the_response The response, which is used in the case that a second
   * factor challenge must be sent to the client.
   * @param the_username the username of the person to attempt to authenticate.
   * @param the_password the password for `username`.
   * @param the_second_factor the second factor for `username`.
   */
  //@ requires 0 < the_username.length();
  //@ requires the_password != null || the_second_factor != null;
  boolean authenticateAdministrator(Request the_request,
                                    Response the_response,
                                    String the_username,
                                    String the_password,
                                    String the_second_factor);

  /**
   * Attempt to authenticate `the_username` using `the_second_factor`.
   * @trace authentication.second_factor_authenticate
   * @return true iff two-factor authentication with credential pair 
   * (username, password) succeeds.
   * @param the_request The request.
   * @param the_username the username of the person to attempt to authenticate.
   * @param the_second_factor the second factor for `username`.
   */
  //@ requires 0 < the_username.length();
  //@ requires the_second_factor != null;
  boolean secondFactorAuthenticate(Request the_request,
                                   String the_username,
                                   String the_second_factor);

  /**
   * Is the session authenticated with a second factor?
   * @trace authenticated.second_factor_authenticated?
   * @param the_request The request.
   * @return true iff the session is second-factor authenticated
   */
  boolean secondFactorAuthenticated(Request the_request);

  /**
   * @trace authentication.traditional_authenticate
   * @return true iff traditional authentication with credential pair 
   * (username, password) succeeds.
   * @param the_request The request.
   * @param the_response The response.
   * @param the_username the username of the person to attempt to authenticate.
   * @param the_password the password for `username`.
   */
  //@ requires 0 < the_username.length();
  //@ requires the_password != null;
  AuthenticationResult traditionalAuthenticate(Request the_request,
                                               Response the_response,
                                               String the_username, 
                                               String the_password);

  /**
   * @trace authentication.traditional_authenticated?
   * @return true iff the session is traditionally authenticated.
   * @param the_request The request.
   */
  boolean traditionalAuthenticated(Request the_request);
  
  /**
   * @return true iff the session is authenticated either traditionally
   * or with a second factor.
   */
  boolean authenticated(Request the_request);
  
  /**
   * @return true iff the session is authenticated in any way
   * as the specified administrator type and username.
   * @param the_request The request.
   * @param the_username the username of the person to check.
   * @param the_type the type of the administrator.
   */
  boolean authenticatedAs(Request the_request,
                            AdministratorType the_type,
                            String the_username);
     
  /**
   * @return true iff the session is authenticated with a second factor
   * as the specified administrator type and username.
   * @param the_request The request.
   * @param the_username the username of the person to check.
   * @param the_type the type of the administrator.
   */
  boolean secondFactorAuthenticatedAs(Request the_request,
                                      AdministratorType the_type,
                                      String the_username);
  
  /**
   * Deauthenticate the currently authenticated user.
   * @param the_request The request.
   */
  void deauthenticate(Request the_request);
      
  /**
   * @trace authentication.traditional_deauthenticate
   * @param the_request The request.
   * @param the_username the user to deauthenticate.
   */
  //@ ensures (* If `the_username` was logged in via traditional authentication, 
  //@            now they are not. *);
  void traditionalDeauthenticate(Request the_request,
                                 String the_username);

  /**
   * @trace authentication.two_factor_deauthenticate
   * @param the_request The request.
   * @param the_username the user to deauthenticate.
   */
  //@ ensures (* If `the_username` was logged in via two-factor authentication, 
  //@            now they are not. *);
  void twoFactorDeauthenticate(Request the_request,
                               String the_username);
  
  /**
   * Gets the authenticated county for a request.
   * 
   * @param the_request The request.
   * @return the authenticated county, or null if this session is not authenticated 
   * as a county administrator.
   */
  County authenticatedCounty(Request the_request);
  
  /** 
   * Gets the authenticated administrator for a request.
   * 
   * @param the_request The request.
   * @return the authenticated administrator, or null if this session is not 
   * authenticated.
   */
  Administrator authenticatedAdministrator(Request the_request);
  
  /**
   * Gets an authentication response based on the current status of a request.
   * 
   * @param the_request The request.
   * @return the authentication response.
   */
  AuthenticationStatus authenticationStatus(Request the_request);
  
  /**
   * Gets the authenticated username
   */
  /**
   * @return the submitted credentials associated with any request.
   * @param the_request The request.
   */
  SubmittedCredentials authenticationCredentials(Request the_request);
}