/*
 * Free & Fair Colorado RLA System
 *
 * @title ColoradoRLA
 * @created Aug 13, 2017
 * @copyright 2017 Colorado Department of State
 * @license SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator Daniel M. Zimmerman <dmz@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.json;

import us.freeandfair.corla.model.CastVoteRecord;

/**
 * A submitted audit CVR.
 *
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 1.0.0
 */
public class SubmittedAuditCVR {
  /**
   * The original CVR ID for this audit CVR.
   */
  private final Long my_cvr_id;

  /**
   * The audit CVR.
   */
  private final CastVoteRecord my_audit_cvr;


  /** flag to indicate whether this is a review-and-reaudit submission
   * - needs to not be final so it can be optional and have a default
   **/
  private final Boolean reaudit;

  /** a comment is required to explain why a reaudit is happening **/
  private final String comment;

  /** the audit board is used for reporting **/
  private final Integer auditBoardIndex;

  /**
   * Constructs a new SubmittedAuditCVR.
   *
   * @param the_cvr_id The original CVR ID.
   * @param the_audit_cvr The audit CVR.
   */
  public SubmittedAuditCVR(final Long the_cvr_id, final CastVoteRecord the_audit_cvr) {
    my_cvr_id = the_cvr_id;
    my_audit_cvr = the_audit_cvr;
    this.reaudit = false;
    this.comment = "";
    this.auditBoardIndex = -1;
  }

  /** create the object with all the fields **/
  public SubmittedAuditCVR(final Long the_cvr_id,
                           final CastVoteRecord the_audit_cvr,
                           final Boolean reaudit,
                           final String comment,
                           final Integer auditBoardIndex) {
    my_cvr_id = the_cvr_id;
    my_audit_cvr = the_audit_cvr;
    this.reaudit = reaudit;
    this.comment = comment;
    this.auditBoardIndex = auditBoardIndex;
  }


  /**
   * @return the original CVR ID.
   */
  public Long cvrID() {
    return my_cvr_id;
  }

  /**
   * @return the audit CVR.
   */
  public CastVoteRecord auditCVR() {
    return my_audit_cvr;
  }

  /** reaudit can be null because it is optional **/
  public Boolean isReaudit() {
    return this.reaudit != null && this.reaudit;
  }

  /** get the comment **/
  public String getComment() {
    return this.comment;
  }

  /** get which audit board is submitting this **/
  public Integer getAuditBoardIndex() {
    return this.auditBoardIndex;
  }

}
