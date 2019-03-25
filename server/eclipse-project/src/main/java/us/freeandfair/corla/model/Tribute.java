package us.freeandfair.corla.model;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Version;
import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import us.freeandfair.corla.persistence.PersistentEntity;

/**
 *  I volunteer as tribute,
 *  to be randomly selected and audited.
 *  A tribute is a theoretical cvr that may or may not exist.
 **/
@Entity
public class Tribute implements PersistentEntity, Serializable {
  /**
   * The serialVersionUID.
   */
  private static final long serialVersionUID = 1;

  /**
   * The version (for optimistic locking).
   */
  @Version
  private Long version;

  /**
   * The ID number.
   */
  @Id
  @Column(updatable = false, nullable = false)
  @GeneratedValue(strategy = GenerationType.SEQUENCE)
  private Long my_id;

  /**
   * A county id
   */
  public Long countyId;

  /**
   * A scanner id
   */
  public Integer scannerId;

  /**
   * A batch id
   */
  public String batchId;

  /**
   * A ballot's position as an offest
   */
  public Integer ballotPosition;

  /**
   * The generated random number that selects/resolves to this Tribute
   */
  public Integer rand;

  /**
   * to preserve the order of randomly selected cvrs
   **/
  public Integer randSequencePosition;

  /**
   * the contest this tribute was selected for
   **/
  public String contestName;

  /**
   * combine attributes to form a uri for fast selection
   */
  public String uri;

  /**
   * {@inheritDoc}
   */
  @Override
  public Long version() {
    return this.version;
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

  /** get the uri **/
  public String getUri() {
    return this.uri;
  }

  /**
   * set the uri for the cvr that is to be selected
   * this is used to find the cvr later
   **/
  public void setUri() {
    this.uri = String.format("%s:%s:%s-%s-%s", "cvr", countyId, scannerId, batchId, ballotPosition);
  }

}
