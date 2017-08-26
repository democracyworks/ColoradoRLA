/*
 * Free & Fair Colorado RLA System
 * 
 * @title ColoradoRLA
 * @created Jul 25, 2017
 * @copyright 2017 Free & Fair
 * @license GNU General Public License 3.0
 * @author Joey Dodds <jdodds@galois.com>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.model;

import static us.freeandfair.corla.util.EqualsHashcodeHelper.nullableEquals;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;

import us.freeandfair.corla.persistence.AbstractEntity;

/**
 * Information about the locations of specific batches of ballots.
 * 
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @version 0.0.1
 */
@Entity
@Table(name = "ballot_manifest_info",
       indexes = { @Index(name = "idx_bmi_county", columnList = "county_id") })
// this class has many fields that would normally be declared final, but
// cannot be for compatibility with Hibernate and JPA.
@SuppressWarnings("PMD.ImmutableField")
public class BallotManifestInfo extends AbstractEntity implements Serializable {
  /**
   * The serialVersionUID.
   */
  private static final long serialVersionUID = 1; 
  
  /**
   * The ID number of the county in which the batch was scanned.
   */
  @Column(name = "county_id", updatable = false, nullable = false)
  private Long my_county_id;
  //@ private invariant my_county_id >= 0;
  
  /**
   * The ID number of the scanner that scanned the batch.
   */
  @Column(updatable = false, nullable = false)
  private String my_scanner_id;

  /**
   * The batch number.
   */
  @Column(updatable = false, nullable = false)
  private String my_batch_id;
  
  /**
   * The size of the batch.
   */
  @Column(updatable = false, nullable = false)
  private Integer my_batch_size;
  
  /**
   * The storage location for the batch.
   */
  @Column(updatable = false, nullable = false)
  private String my_storage_location;
 
  /** 
   * Constructs an empty ballot manifest information record, solely
   * for persistence.
   */
  public BallotManifestInfo() {
    super();
  }
  
  /**
   * Constructs a ballot manifest information record.
   * 
   * @param the_county_id The county ID.
   * @param the_scanner_id The scanner ID.
   * @param the_batch_id The batch ID.
   * @param the_batch_size The batch size.
   * @param the_storage_location The storage location.
   */
  public BallotManifestInfo(final Long the_county_id,
                            final String the_scanner_id, 
                            final String the_batch_id,
                            final int the_batch_size, 
                            final String the_storage_location) {
    super();
    my_county_id = the_county_id;
    my_scanner_id = the_scanner_id;
    my_batch_id = the_batch_id;
    my_batch_size = the_batch_size;
    my_storage_location = the_storage_location;
  }
  
  /**
   * @return the county ID.
   */
  public Long countyID() {
    return my_county_id;
  }  

  /**
   * @return the scanner ID.
   */
  public String scannerID() {
    return my_scanner_id;
  }
  
  /**
   * @return the batch number.
   */
  public String batchID() {
    return my_batch_id;
  }
  
  /**
   * @return the batch size.
   */
  public Integer batchSize() {
    return my_batch_size;
  }
  
  /**
   * @return the storage container number.
   */
  public String storageLocation() {
    return my_storage_location;
  }  
  
  /**
   * @return a String representation of this object.
   */
  @Override
  public String toString() {
    return "BallotManifestInfo [" + ", county_id=" + my_county_id + 
           ", scanner_id=" + my_scanner_id + ", batch_size=" + 
           my_batch_size + ", storage_container=" + my_storage_location + "]";
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
    if (the_other instanceof BallotManifestInfo) {
      final BallotManifestInfo other_bmi = (BallotManifestInfo) the_other;
      result &= nullableEquals(other_bmi.id(), id());
    } else {
      result = false;
    }
    return result;
  }
  
  /**
   * @return a hash code for this object.
   */
  @Override
  public int hashCode() {
    return id().hashCode();
  }
}
