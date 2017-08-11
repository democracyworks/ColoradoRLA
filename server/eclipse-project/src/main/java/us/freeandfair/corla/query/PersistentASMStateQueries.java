/*
 * Free & Fair Colorado RLA System
 * 
 * @title ColoradoRLA
 * @created Aug 11, 2017
 * @copyright 2017 Free & Fair
 * @license GNU General Public License 3.0
 * @author Daniel M. Zimmerman <dmz@galois.com>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.query;

import java.util.List;

import javax.persistence.PersistenceException;
import javax.persistence.RollbackException;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

import org.hibernate.Session;

import us.freeandfair.corla.Main;
import us.freeandfair.corla.asm.AbstractStateMachine;
import us.freeandfair.corla.asm.PersistentASMState;
import us.freeandfair.corla.persistence.Persistence;

/**
 * Queries having to do with persistent ASM state.
 * 
 * @author Daniel M. Zimmerman
 * @version 0.0.1
 */
public final class PersistentASMStateQueries {
  /**
   * Private constructor to prevent instantiation.
   */
  private PersistentASMStateQueries() {
    // do nothing
  }
  
  /**
   * Retrieves the persistent ASM state from the database matching the specified
   * ASM class and identity, if one exists.
   * 
   * @param the_class The class of ASM to retrieve. 
   * @param the_identity The identity of the ASM to retrieve, or null if the ASM
   * is a singleton.
   * @return the persistent ASM state, or null if it does not exist.
   */
  // we are checking to see if exactly one result is in a list, and
  // PMD doesn't like it
  @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
  public static PersistentASMState get(final Class<? extends AbstractStateMachine> the_class,
                                       final String the_identity) {
    PersistentASMState result = null;
    try {
      final String class_name = the_class.getName();
      final boolean transaction = Persistence.beginTransaction();
      final Session s = Persistence.currentSession();
      final CriteriaBuilder cb = s.getCriteriaBuilder();
      final CriteriaQuery<PersistentASMState> cq = cb.createQuery(PersistentASMState.class);
      final Root<PersistentASMState> root = cq.from(PersistentASMState.class);
      
      cq.select(root).where(cb.and(cb.equal(root.get("my_asm_class"), class_name),
                                   cb.equal(root.get("my_asm_identity"), the_identity)));
      final TypedQuery<PersistentASMState> query = s.createQuery(cq);
      final List<PersistentASMState> query_results = query.getResultList();
      
      PersistentASMState asm = null;
      if (query_results.size() > 1) {
        Main.LOGGER.error("multiple ASM states found");
      } else if (!query_results.isEmpty()) {
        asm = query_results.get(0);
      }
      if (transaction) {
        try {
          Persistence.commitTransaction();
        } catch (final RollbackException e) {
          Main.LOGGER.error("could not get persistent ASM state");
          Persistence.rollbackTransaction();
        }
      }
      result = asm;
    } catch (final PersistenceException e) {
      Main.LOGGER.error("could not query database for persistent ASM state");
    }
    return result;
  }

}
