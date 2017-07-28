/*
 * Free & Fair Colorado RLA System
 * 
 * @title ColoradoRLA
 * @created Jul 27, 2017
 * @copyright 2017 Free & Fair
 * @license GNU General Public License 3.0
 * @author Daniel M. Zimmerman <dmz@freeandfair.us>
 * @description A system to assist in conducting statewide risk-limiting audits.
 */

package us.freeandfair.corla.endpoint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;

import org.eclipse.jetty.http.HttpStatus;

import spark.Request;
import spark.Response;

import us.freeandfair.corla.Main;
import us.freeandfair.corla.csv.CVRExportParser;
import us.freeandfair.corla.csv.DominionCVRExportParser;
import us.freeandfair.corla.model.CastVoteRecord;

/**
 * The "CVR upload" endpoint.
 * 
 * @author Daniel M. Zimmerman
 * @version 0.0.1
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public class CVRUpload implements Endpoint {
  /**
   * {@inheritDoc}
   */
  @Override
  public EndpointType endpointType() {
    return EndpointType.POST;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override
  public String endpointName() {
    return "/upload-cvr-export";
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public String endpoint(final Request the_request, final Response the_response) {
    // this is a multipart request - there's a "county" identifier, and a "cvr_file"
    // containing the actual file
    the_request.attribute("org.eclipse.jetty.multipartConfig", 
                          new MultipartConfigElement("/tmp"));
    boolean ok = true;
    try (InputStream county_is = the_request.raw().getPart("county").getInputStream()) {
      final InputStreamReader county_isr = new InputStreamReader(county_is);
      final BufferedReader br = new BufferedReader(county_isr);
      final String county = br.lines().collect(Collectors.joining("\n"));
      try (InputStream cvr_is = the_request.raw().getPart("cvr_file").getInputStream()) {
        final InputStreamReader cvr_isr = new InputStreamReader(cvr_is);
        final CVRExportParser parser = new DominionCVRExportParser(cvr_isr, county);
        ok = parser.parse();
        Main.LOGGER.info(parser.cvrs().size() + " CVRs parsed from " + county + 
                         " county upload file");
        Main.LOGGER.info(CastVoteRecord.getCVRs(null, true).size() + 
                         " uploaded CVRs in storage");
      } catch (final IOException | ServletException e) {
        ok = false;
      }
    } catch (final IOException | ServletException e) {
      ok = false;
    }
    
    if (ok) {
      return "OK";
    } else {
      the_response.status(HttpStatus.UNPROCESSABLE_ENTITY_422);
      return "Not OK";
    }
  }
}
