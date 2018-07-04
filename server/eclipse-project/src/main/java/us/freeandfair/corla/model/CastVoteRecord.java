/*
 * Free & Fair Colorado RLA System
 *
 * @title ColoradoRLA
 * @created Jul 25, 2017
 * @copyright 2017 Colorado Department of State
 * @license SPDX-License-Identifier: AGPL-3.0-or-later
 * @creator Daniel M. Zimmerman <dmz@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.model;

import static us.freeandfair.corla.util.EqualsHashcodeHelper.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.persistence.Cacheable;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.JoinColumn;
import javax.persistence.OrderColumn;
import javax.persistence.Table;
import javax.persistence.Version;

import org.hibernate.annotations.Immutable;

import us.freeandfair.corla.persistence.PersistentEntity;
import us.freeandfair.corla.util.NaturalOrderComparator;
import us.freeandfair.corla.util.SuppressFBWarnings;

/**
 * A cast vote record contains information about a single ballot, either
 * imported from a tabulator export file or generated by auditors.
 *
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 1.0.0
 */
@Entity
@Immutable // this is a Hibernate-specific annotation, but there is no JPA alternative
@Cacheable(false)
@Table(name = "cast_vote_record",
       indexes = { @Index(name = "idx_cvr_county_type", columnList = "county_id, record_type"),
                   @Index(name = "idx_cvr_county_cvr_number",
                          columnList = "county_id, cvr_number"),
                   @Index(name = "idx_cvr_county_cvr_number_type",
                          columnList = "county_id, cvr_number, record_type"),
                   @Index(name = "idx_cvr_county_sequence_number_type",
                          columnList = "county_id, sequence_number, record_type"),
                   @Index(name = "idx_cvr_county_imprinted_id_type",
                          columnList = "county_id, imprinted_id, record_type")})
// this class has many fields that would normally be declared final, but
// cannot be for compatibility with Hibernate and JPA.
@SuppressWarnings("PMD.ImmutableField")
// this FindBugs warning is for the transient field, which we know will not be
// restored when the class is unserialized, because we intentionally made it
// transient so it wouldn't be. Since that's what "transient" means.
@SuppressFBWarnings("SE_TRANSIENT_FIELD_NOT_RESTORED")
public class CastVoteRecord implements PersistentEntity, Serializable {
  /**
   * The serialVersionUID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * The ID number.
   */
  @Id
  @Column(updatable = false, nullable = false)
  @GeneratedValue(strategy = GenerationType.SEQUENCE)
  private Long my_id;

  /**
   * The version (for optimistic locking).
   */
  @Version
  private Long my_version;

  /**
   * A flag indicating whether this record was generated by auditors or
   * by import.
   */
  @Column(name = "record_type", updatable = false, nullable = false)
  @Enumerated(EnumType.STRING)
  private RecordType my_record_type;

  /**
   * The timestamp of this cast vote record; used only for ACVRs.
   */
  @Column(updatable = false)
  private Instant my_timestamp;

  /**
   * The county ID of this cast vote record.
   */
  @Column(name = "county_id", updatable = false, nullable = false)
  private Long my_county_id;

  /**
   * The CVR number of this cast vote record.
   */
  @Column(name = "cvr_number", updatable = false, nullable = false)
  private Integer my_cvr_number;

  /**
   * The sequence number of this cast vote record. Only applicable
   * to imported CVRs.
   */
  @Column(name = "sequence_number", updatable = false)
  private Integer my_sequence_number;

  /**
   * The scanner ID of this cast vote record.
   */
  @Column(updatable = false, nullable = false)
  private Integer my_scanner_id;

  /**
   * The batch ID of this cast vote record.
   */
  @Column(updatable = false, nullable = false)
  private String my_batch_id;

  /**
   * The record ID of this cast vote record.
   */
  @Column(updatable = false, nullable = false)
  private Integer my_record_id;

  /**
   * The imprinted ID of this cast vote record.
   */
  @Column(name = "imprinted_id", updatable = false, nullable = false)
  private String my_imprinted_id;

  /**
   * The ballot style of this cast vote record.
   */
  @Column(updatable = false, nullable = false)
  private String my_ballot_type;

  /**
   * The contest information in this cast vote record.
   */
  @ElementCollection(fetch = FetchType.EAGER)
  @OrderColumn(name = "index")
  @CollectionTable(name = "cvr_contest_info",
                   joinColumns = @JoinColumn(name = "cvr_id",
                                             referencedColumnName = "my_id"))
  private List<CVRContestInfo> my_contest_info = new ArrayList<>();

  /**
   * A transient flag that indicates whether this CVR was audited; this is only
   * used for passing information around within the RLA tool and is not serialized
   * in the database; the authoritative source of information about whether a CVR
   * has been audited, and in what audit, is the responsible audit information
   * object.
   */
  private transient boolean my_audit_flag;

  /**
   * Constructs an empty cast vote record, solely for persistence.
   */
  public CastVoteRecord() {
    super();
  }

  /**
   * Constructs a new cast vote record.
   *
   * @param the_record_type The type.
   * @param the_timestamp The timestamp.
   * @param the_county_id The county ID.
   * @param the_cvr_number The CVR number (as imported).
   * @param the_sequence_number The sequence number, if applicable.
   * @param the_scanner_id The scanner ID.
   * @param the_batch_id The batch ID.
   * @param the_record_id The record ID.
   * @param the_imprinted_id The imprinted ID.
   * @param the_ballot_type The ballot type.
   * @param the_contest_info A map of the choices made in each contest.
   */
  @SuppressWarnings("PMD.ExcessiveParameterList")
  public CastVoteRecord(final RecordType the_record_type,
                        final Instant the_timestamp,
                        final Long the_county_id,
                        final Integer the_cvr_number,
                        final Integer the_sequence_number,
                        final Integer the_scanner_id,
                        final String the_batch_id,
                        final Integer the_record_id,
                        final String the_imprinted_id,
                        final String the_ballot_type,
                        final List<CVRContestInfo> the_contest_info) {
    super();
    my_record_type = the_record_type;
    my_timestamp = the_timestamp;
    my_county_id = the_county_id;
    my_cvr_number = the_cvr_number;
    my_sequence_number = the_sequence_number;
    my_scanner_id = the_scanner_id;
    my_batch_id = the_batch_id;
    my_record_id = the_record_id;
    my_imprinted_id = the_imprinted_id;
    my_ballot_type = the_ballot_type;
    if (the_contest_info != null) {
      my_contest_info.addAll(the_contest_info);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Long id() {
    return my_id;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void setID(final Long the_id) {
    my_id = the_id;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Long version() {
    return my_version;
  }

  /**
   * @return this record's type.
   */
  public RecordType recordType() {
    return my_record_type;
  }

  /**
   * @return the timestamp of this record.
   */
  public Instant timestamp() {
    return my_timestamp;
  }

  /**
   * @return the county ID.
   */
  public Long countyID() {
    return my_county_id;
  }

  /**
   * @return the CVR number (as imported).
   */
  public Integer cvrNumber() {
    return my_cvr_number;
  }

  /**
   * @return the CVR sequence number.
   */
  public Integer sequenceNumber() {
    return my_sequence_number;
  }

  /**
   * @return the scanner ID.
   */
  public Integer scannerID() {
    return my_scanner_id;
  }

  /**
   * @return the batch ID.
   */
  public String batchID() {
    return my_batch_id;
  }

  /**
   * @return the record ID.
   */
  public Integer recordID() {
    return my_record_id;
  }

  /**
   * @return the imprinted ID for this cast vote record.
   */
  public String imprintedID() {
    return my_imprinted_id;
  }

  /**
   * @return the ballot type for this cast vote record.
   */

  public String ballotType() {
    return my_ballot_type;
  }

  /**
   * @return the choices made in this cast vote record.
   */
  public List<CVRContestInfo> contestInfo() {
    return Collections.unmodifiableList(my_contest_info);
  }

  /**
   * Gets the choices for the specified contest.
   *
   * @param the_contest The contest.
   * @return the choices made in this cast vote record for the specified contest,
   * or null if none were made for the specified contest.
   */
  public CVRContestInfo contestInfoForContest(final Contest the_contest) {
    for (final CVRContestInfo info : my_contest_info) {
      if (info.contest().equals(the_contest)) {
        return info;
      }
    }
    return null;
  }

  /**
   * @return the audit flag. This flag is meaningless unless it was explicitly set
   * when this record was loaded. It is useful only for communicating information
   * about a CVR within a specific computation of the tool, and is not serialized
   * in the database; the authoritative source of information about whether a CVR
   * has been audited, and in what audit, is the responsible audit information
   * object.
   */
  public boolean auditFlag() {
    return my_audit_flag;
  }

  /**
   * Sets the audit flag.
   *
   * @param the_audit_flag The new flag.
   */
  public void setAuditFlag(final boolean the_audit_flag) {
    my_audit_flag = the_audit_flag;
  }

  /**
   * @return a String representation of this cast vote record.
   */
  @Override
  public String toString() {
    return "CastVoteRecord [record_type=" + my_record_type + ", timestamp=" +
           my_timestamp + ", county_id=" + my_county_id + ", cvr_id=" + my_cvr_number +
           ", scanner_id=" + my_scanner_id + ", batch_id=" + my_batch_id + ", record_id=" +
           my_record_id + ", imprinted_id=" + my_imprinted_id + ", ballot_type=" +
           my_ballot_type + ", contest_info=" + my_contest_info + "]";
  }

  /**
   * Compare this object with another for equivalence.
   *
   * @param the_other The other object.
   * @return true if the objects are equivalent, false otherwise.
   */
  @Override
  public boolean equals(final Object the_other) {
    boolean result = true;
    if (the_other instanceof CastVoteRecord) {
      final CastVoteRecord other_cvr = (CastVoteRecord) the_other;
      result &= nullableEquals(other_cvr.countyID(), countyID());
      result &= nullableEquals(other_cvr.cvrNumber(), cvrNumber());
      result &= nullableEquals(other_cvr.sequenceNumber(), sequenceNumber());
      result &= nullableEquals(other_cvr.scannerID(), scannerID());
      result &= nullableEquals(other_cvr.batchID(), batchID());
      result &= nullableEquals(other_cvr.recordID(), recordID());
      result &= nullableEquals(other_cvr.imprintedID(), imprintedID());
      result &= nullableEquals(other_cvr.ballotType(), ballotType());
      result &= nullableEquals(other_cvr.contestInfo(), contestInfo());
    } else {
      result = false;
    }
    return result;
  }

  /**
   * Compares this CVR with another to determine whether
   * one is an audit CVR for the other - that is, whether they have
   * the same county ID, scanner ID, batch ID, record ID,
   * imprinted ID, and ballot type, and exactly one of them is an
   * auditor uploaded CVR.
   *
   * @param the_other The other CVR.
   * @return true if one CVR is an audit CVR for the other; false
   * otherwise.
   */
  public boolean isAuditPairWith(final CastVoteRecord the_other) {
    boolean result = true;

    if (the_other == null) {
      result = false;
    } else {
      result &= nullableEquals(the_other.countyID(), countyID());
      result &= nullableEquals(the_other.cvrNumber(), cvrNumber());
      result &= nullableEquals(the_other.scannerID(), scannerID());
      result &= nullableEquals(the_other.batchID(), batchID());
      result &= nullableEquals(the_other.recordID(), recordID());
      result &= nullableEquals(the_other.imprintedID(), imprintedID());
      result &= nullableEquals(the_other.ballotType(), ballotType());
      result &= recordType().isAuditorGenerated() ^
                the_other.recordType().isAuditorGenerated();
    }

    return result;
  }

  /**
   * @return a hash code for this object.
   */
  @Override
  public int hashCode() {
    return nullableHashCode(imprintedID());
  }

  /**
   * An enumeration used to select cast vote record types.
   */
  public enum RecordType {
    UPLOADED, PHANTOM_RECORD, AUDITOR_ENTERED, PHANTOM_BALLOT;

    /**
     * @return true if this record was generated by an auditor,
     * false otherwise.
     */
    public boolean isAuditorGenerated() {
      return this == AUDITOR_ENTERED || this == PHANTOM_BALLOT;
    }
  }

  /**
   * A comparator to sort CastVoteRecord objects by scanner ID, then batch ID,
   * then record ID.
   */
  @SuppressWarnings("PMD.AtLeastOneConstructor")
  public static class BallotOrderComparator
      implements Serializable, Comparator<CastVoteRecord> {
    /**
     * The serialVersionUID.
     */
    private static final long serialVersionUID = 1;

    /**
     * Orders two CastVoteRecord lexicographically by the triple
     * (scanner_id, batch_id, record_id).
     *
     * @param the_first The first CVR.
     * @param the_second The second CVR.
     * @return a positive, negative, or 0 value as the first response is
     * greater than, equal to, or less than the second, respectively.
     */
    @SuppressWarnings("PMD.ConfusingTernary")
    public int compare(final CastVoteRecord the_first, final CastVoteRecord the_second) {
      final int scanner = the_first.scannerID() - the_second.scannerID();
      final int batch = NaturalOrderComparator.INSTANCE.compare(the_first.batchID(),
                                                             the_second.batchID());
      final int record = the_first.recordID() - the_second.recordID();

      final int result;

      if (scanner != 0) {
        result = scanner;
      } else if (batch != 0) {
        result = batch;
      } else {
        result = record;
      }

      return result;
    }
  }
}
