import * as _ from 'lodash';

import * as React from 'react';
import { Link } from 'react-router-dom';

import { Card } from '@blueprintjs/core';

import CountyLayout from 'corla/component/CountyLayout';
import * as config from 'corla/config';

const MissedDeadlinePage = () => {
    const main =
        <div>
            <h2>Upload Deadline Missed</h2>
            <div>
                <Card>
                    You are unable to upload a file because the deadline has passed and the
                    audit has begun. Please contact the CDOS voting systems team at&nbsp;
                    <strong>{ config.helpEmail }</strong> or <strong>{ config.helpTel }</strong> for assistance.
                </Card>
            </div>
        </div>;

    return <CountyLayout main={ main } />;
};

export default MissedDeadlinePage;
