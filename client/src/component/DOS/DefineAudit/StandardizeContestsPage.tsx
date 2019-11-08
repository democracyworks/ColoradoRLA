import * as React from 'react';

import * as _ from 'lodash';

import { Breadcrumb, Button, Card, Intent } from '@blueprintjs/core';

import DOSLayout from 'corla/component/DOSLayout';
import counties from 'corla/data/counties';

import { findBestMatch } from 'string-similarity';

/**
 * The maximum percentage match at or above which a contest will be assumed to
 * match a given canonical contest.
 *
 * The algorithm used is not defined, so this may need to change if the
 * algorithm is changed.
 */
const MIN_MATCH_THRESHOLD = 0.67;

/**
 * Returns the default selection for `name` given `canonicalNames` to choose
 * from.
 *
 * The default selection will be the empty string if there was not a better
 * choice in `canonicalNames` for the given contest name.
 */
const defaultCanonicalName = (
    name: string,
    canonicalNames: string[],
): string => {
    const loweredName = name.toLowerCase();
    const loweredCanonicals = _.map(canonicalNames, s => s.toLowerCase());

    const { bestMatch, bestMatchIndex } = findBestMatch(
        loweredName,
        loweredCanonicals,
    );

    if (bestMatch.rating < MIN_MATCH_THRESHOLD) {
        return '';
    }

    return canonicalNames[bestMatchIndex];
};

const Breadcrumbs = () => (
    <ul className='pt-breadcrumbs mb-default'>
        <li><Breadcrumb href='/sos' text='SoS' />></li>
        <li><Breadcrumb href='/sos/audit' text='Audit Admin' /></li>
        <li><Breadcrumb className='pt-breadcrumb-current' text='Standardize Contest Names' /></li>
    </ul>
);

interface UpdateFormMessage {
    id: number;
    name: string;
}

interface TableProps {
    contests: DOS.Contests;
    canonicalContests: DOS.CanonicalContests;
    updateFormData: (msg: UpdateFormMessage) => void;
}

const StandardizeContestsTable = (props: TableProps) => {
    const { canonicalContests, contests, updateFormData } = props;

    return (
        <table className='pt-html-table pt-html-table-striped'>
            <thead>
                <tr>
                    <th>County</th>
                    <th>Current Contest Name</th>
                    <th>Standardized Contest Name</th>
                </tr>
            </thead>
            <ContestBody contests={ contests }
                         canonicalContests={ canonicalContests }
                         updateFormData={ updateFormData } />
        </table>
    );
};

interface BodyProps {
    contests: DOS.Contests;
    canonicalContests: DOS.CanonicalContests;
    updateFormData: (msg: UpdateFormMessage) => void;
}

const ContestBody = (props: BodyProps) => {
    const { canonicalContests, contests, updateFormData } = props;

    const rows = _.map(contests, c => {
        return <ContestRow key={ c.id }
                           contest={ c }
                           canonicalContests={ canonicalContests }
                           updateFormData={ updateFormData } />;
    });

    return (
      <tbody>{ rows }</tbody>
    );
};

interface ContestRowProps {
    contest: Contest;
    canonicalContests: DOS.CanonicalContests;
    updateFormData: (msg: UpdateFormMessage) => void;
}

const ContestRow = (props: ContestRowProps) => {
    const { canonicalContests, contest, updateFormData } = props;
    const countyName = counties[contest.countyId].name;

    const standards = canonicalContests[countyName];

    const defaultName = '';

    const changeHandler = (e: React.FormEvent<HTMLSelectElement>) => {
        const v = e.currentTarget.value;

        updateFormData({ id: contest.id, name: v });
    };

    return (
        <tr>
            <td>{ counties[contest.countyId].name }</td>
            <td>{ contest.name }</td>
            <td>
                <form>
                    <select className='max-width-select'
                            name={ String(contest.id) }
                            onChange={ changeHandler }
                            defaultValue={ defaultName }>
                        <option value=''>-- No change --</option>
                        {
                          _.map(standards, n => <option value={ n }>{ n }</option>)
                        }
                    </select>
                </form>
            </td>
        </tr>
    );
};

interface PageProps {
    areContestsLoaded: boolean;
    canonicalContests: DOS.CanonicalContests;
    contests: DOS.Contests;
    forward: (x: DOS.Form.StandardizeContests.FormData) => void;
    back: () => void;
}

class StandardizeContestsPage extends React.Component<PageProps> {
    public formData: DOS.Form.StandardizeContests.FormData = {};

    public constructor(props: PageProps) {
        super(props);

        this.updateFormData = this.updateFormData.bind(this);
    }

    public render() {
        const {
            areContestsLoaded,
            back,
            canonicalContests,
            contests,
            forward,
        } = this.props;

        let main = null;

        if (areContestsLoaded) {
            this.formData = {};

            main =
                <div>
                    <Breadcrumbs />
                    <h2 className='mb-default'>Standardize Contest Names</h2>
                    <Card>
                        <p>
                            Contest names must be standardized to group records
                            correctly across jurisdictions. Below is a list of
                            contests that do not match the standardized contest
                            names provided by the state. For each of the contests
                            listed, please choose the appropriate standardized
                            version from the options provided, then save your
                            selections and move forward.
                        </p>

                        <StandardizeContestsTable canonicalContests={ canonicalContests }
                                                  contests={ contests }
                                                  updateFormData={ this.updateFormData } />
                    </Card>
                    <Button onClick={ back }>Back</Button>
                    <Button className='ml-default'
                            intent={ Intent.PRIMARY }
                            onClick={ () => forward(this.formData) }>
                        Save & Next
                    </Button>
                </div>;
        } else {
            main =
                <div>
                    <Breadcrumbs />
                    <h2 className='mb-default'>Standardize Contest Names</h2>
                    <div  className='mb-default'>
                        <Card>
                            Waiting for counties to upload contest data.
                        </Card>
                    </div>
                    <Button onClick={ back }>Back</Button>
                    <Button className='ml-default'
                            disabled
                            intent={ Intent.PRIMARY }>
                        Save & Next
                    </Button>
                </div>;
        }

        return <DOSLayout main={ main } />;
    }

    private updateFormData(msg: UpdateFormMessage) {
        const { id, name } = msg;

        if (_.isEmpty(name)) {
            delete this.formData[id];
        } else {
            this.formData[id] = { name };
        }
    }
}

export default StandardizeContestsPage;
