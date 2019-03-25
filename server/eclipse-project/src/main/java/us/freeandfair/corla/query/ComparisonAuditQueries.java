/*
 * Free & Fair Colorado RLA System
 *
 * @title ColoradoRLA
 * @copyright 2018 Colorado Department of State
 * @license SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator Democracy Works, Inc <dev@democracy.works>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.query;

import org.hibernate.query.Query;
import org.hibernate.Session;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import us.freeandfair.corla.model.AuditStatus;
import us.freeandfair.corla.model.ComparisonAudit;
import us.freeandfair.corla.persistence.Persistence;

/**
 * Queries having to do with ComparisonAudit entities.
 */
public final class ComparisonAuditQueries {
  /**
   * Class-wide logger
   */
  public static final Logger LOGGER =
      LogManager.getLogger(ComparisonAuditQueries.class);

  /**
   * Private constructor to prevent instantiation.
   */
  private ComparisonAuditQueries() {
    // do nothing
  }

  /**
   * Obtain the ComparisonAudit object for the specified contest name.
   *
   * @param contestName The contest name
   * @return the matched object
   */
  public static ComparisonAudit matching(final String contestName) {
    final Session s = Persistence.currentSession();
    final Query q =
      s.createQuery("select ca from ComparisonAudit ca "
                    + " join ContestResult cr "
                    + "   on ca.my_contest_result = cr "
                    + " where cr.contestName = :contestName");

    q.setParameter("contestName", contestName);

    try {
      return (ComparisonAudit) q.getSingleResult();
    } catch (javax.persistence.NoResultException e ) {
      return null;
    }
  }


  /**
   * Return the ContestResult with the contestName given or create a new
   * ContestResult with the contestName.
   **/
  public static Integer count() {
    final Session s = Persistence.currentSession();
    final Query q = s.createQuery("select count(ca) from ComparisonAudit ca");
    return ((Long)q.uniqueResult()).intValue();
  }

  /** setAuditStatus on matching contestName **/
  public static void updateStatus(final String contestName, final AuditStatus auditStatus) {
    final ComparisonAudit ca = matching(contestName);
    if (null != ca) {
      ca.setAuditStatus(auditStatus);
    }
  }
}
