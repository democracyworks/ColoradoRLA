import { endpoint } from '../../config';

import createFileFetchAction from '../createFileFetchAction';


const url = endpoint('county-report');


export default createFileFetchAction({
    failType: 'COUNTY_FETCH_REPORT_FAIL',
    networkFailType: 'COUNTY_FETCH_REPORT_NETWORK_FAIL',
    okType: 'COUNTY_FETCH_REPORT_OK',
    sendType: 'COUNTY_FETCH_REPORT_SEND',
    url,
});