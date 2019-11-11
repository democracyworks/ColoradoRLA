import * as React from 'react';

import * as _ from 'lodash';

import { Breadcrumb, Button, Card, Intent } from '@blueprintjs/core';

import DOSLayout from 'corla/component/DOSLayout';

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
 * choice in `canonicalNames` for the given choice name.
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
        <Breadcrumb href='/sos' />
        <Breadcrumb href='/sos/audit' />
        <Breadcrumb className='pt-breadcrumb-current' />
    </ul>
);

interface UpdateFormMessage {
    contestId: number;
    currentChoiceName: string;
    newChoiceName: string;
}

interface TableProps {
    contests: DOS.Contests;
    formData: DOS.Form.StandardizeChoices.FormData;
    rows: DOS.Form.StandardizeChoices.Row[];
    updateFormData: (msg: UpdateFormMessage) => void;
}

const Table = (props: TableProps) => {
    const { contests, formData, rows, updateFormData } = props;

    return (
        <table className='pt-html-table pt-html-table-striped'>
            <thead>
                <tr>
                    <th>County Name</th>
                    <th>Contest Name</th>
                    <th>Current Choice Name</th>
                    <th>Standardized Choice Name</th>
                </tr>
            </thead>
            <TableBody contests={ contests }
                       rows={ rows }
                       formData={ formData }
                       updateFormData={ updateFormData } />
        </table>
    );
};

interface TableBodyProps {
    contests: DOS.Contests;
    formData: DOS.Form.StandardizeChoices.FormData;
    rows: DOS.Form.StandardizeChoices.Row[];
    updateFormData: (msg: UpdateFormMessage) => void;
}

const TableBody = (props: TableBodyProps) => {
    const { contests, formData, rows, updateFormData } = props;

    const key = (row: DOS.Form.StandardizeChoices.Row) =>
        row.countyName + ',' + row.contestName + ',' + row.choiceName;

    return (
        <tbody>
        {
            _.map(rows, row =>
                <TableRow key={ key(row) }
                          formData={ formData }
                          row={ row }
                          updateFormData={ updateFormData} />)
        }
        </tbody>
    );
};

interface TableRowProps {
    row: DOS.Form.StandardizeChoices.Row;
    formData: DOS.Form.StandardizeChoices.FormData;
    updateFormData: (msg: UpdateFormMessage) => void;
}

const TableRow = (props: TableRowProps) => {
    const { row, formData, updateFormData } = props;

    const choices = row.choices;

    const changeHandler = (e: React.FormEvent<HTMLSelectElement>) => {
        const v = e.currentTarget.value;

        updateFormData({
            contestId: row.contestId,
            currentChoiceName: row.choiceName,
            newChoiceName: v,
        });
    };

    return (
        <tr>
            <td>{ row.countyName }</td>
            <td>{ row.contestName }</td>
            <td>{ row.choiceName }</td>
            <td>
                <form>
                    <select className='max-width-select'
                            onChange={ changeHandler }
                            value={ _.get(formData, `${row.contestId }.${row.choiceName}`, '') }>
                        <option key='' value=''>-- No change --</option>
                        {
                            _.map(choices, (choice, idx) => {
                                return <option key={ idx } value={ choice }>{ choice }</option>;
                            })
                        }
                    </select>
                </form>
            </td>
        </tr>
    );
};

interface PageProps {
    areChoicesLoaded: boolean;
    contests: DOS.Contests;
    rows: DOS.Form.StandardizeChoices.Row[];
    forward: (x: DOS.Form.StandardizeChoices.FormData) => void;
    back: () => void;
}

interface PageState {
    formData: DOS.Form.StandardizeChoices.FormData;
}

class Page extends React.Component<PageProps, PageState> {
    public constructor(props: PageProps) {
        super(props);

        this.state = {
            formData: {},
        };

        this.updateFormData = this.updateFormData.bind(this);
    }

    /*
     * Run when choices data loads in and populate the form state with initial
     * choice guesses.
     */
    public componentDidUpdate(prevProps: PageProps, prevState: PageState) {
        if (!prevProps.areChoicesLoaded && this.props.areChoicesLoaded) {
            const { rows } = this.props;

            const formData: DOS.Form.StandardizeChoices.FormData = {};

            _.forEach(rows, row => {
                const { choiceName, choices } = row;

                const defaultChoice = defaultCanonicalName(choiceName, choices);

                if (!_.isEmpty(defaultChoice)) {
                    _.set(formData, `${row.contestId}.${row.choiceName}`, defaultChoice);
                }
            });

            this.setState({ formData });
        }
    }

    public render() {
        const {
            areChoicesLoaded,
            back,
            contests,
            rows,
            forward,
        } = this.props;

        let main = null;

        if (areChoicesLoaded) {
            main =
                <div>
                    <Breadcrumbs />
                    <h2>Standardize Choice Names</h2>
                    <Card>
                        <p>
                            Choice names for each contest must be standardized
                            to group records correctly across jurisdictions.
                            Below is a list of choice names that do not match
                            the standardized names provided for that particular
                            contest by the state. For each of the choices
                            listed, please choose the appropriate standardized
                            version from the options provided, then save your
                            selections and move forward.
                        </p>

                        <Table contests={ contests }
                               formData={ this.state.formData }
                               rows={ rows }
                               updateFormData={ this.updateFormData } />
                    </Card>
                    <Button onClick={ back }
                            className='pt-breadcrumb'>
                        Back
                    </Button>
                    <Button onClick={ () => forward(this.state.formData) }
                            intent={ Intent.PRIMARY }
                            className='pt-breadcrumb'>
                        Save & Next
                    </Button>
                </div>;
        } else {
            main =
                <div>
                    <Breadcrumbs />
                    <h2>Standardize Choice Names</h2>
                    <Card>
                        Waiting for counties to upload choice data.
                    </Card>
                    <Button onClick={ back }
                            className='pt-breadcrumb'>
                        Back
                    </Button>
                    <Button disabled
                            intent={ Intent.PRIMARY }
                            className='pt-breadcrumb'>
                        Save & Next
                    </Button>
                </div>;
        }

        return <DOSLayout main={ main } />;
    }

    private updateFormData(msg: UpdateFormMessage) {
        const { contestId, currentChoiceName, newChoiceName } = msg;

        const formData = this.state.formData;

        if ('' === newChoiceName) {
            delete formData[contestId][currentChoiceName];

            if (_.isEmpty(formData[contestId])) {
                delete formData[contestId];
            }
        } else {
            _.merge(formData, {
                [contestId]: {
                    [currentChoiceName]: newChoiceName,
                },
            });
        }

        this.setState({ formData });
    }
}

export default Page;
