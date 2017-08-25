import * as React from 'react';

import * as _ from 'lodash';

import { Checkbox, EditableText, MenuDivider, Radio, RadioGroup } from '@blueprintjs/core';

import BackButton from './BackButton';

import ballotNotFound from '../../../../action/ballotNotFound';
import countyFetchCvr from '../../../../action/countyFetchCvr';


const BallotNotFoundForm = ({ ballotNotFound, currentBallot }: any) => {
    const onClick = () => ballotNotFound(currentBallot.id);
    return (
        <div>
            <div>
                If the ballot card corresponding to the above Ballot ID, Ballot
                Style, and Imprinted ID cannot be found, select the "Ballot Card Not Found"
                button and you will be given a new ballot card to audit.
            </div>
            <button className='pt-button pt-intent-primary' onClick={ onClick }>
                Ballot Card Not Found
            </button>
        </div>
    );
};

const AuditInstructions = ({ ballotNotFound, ballotsToAudit, currentBallot }: any) => (
    <div className='pt-card'>
        <div>
            Use this page to report the voter markings on the ballot with ID
            #{ currentBallot.id }, out of { ballotsToAudit.length } ballots that you
            must audit.
        </div>
        <div>
            The current ballot is:
            <ul>
                <li>Ballot Type: { currentBallot.ballotType }</li>
                <li>Scanner ID: { currentBallot.scannerId }</li>
                <li>Batch ID: { currentBallot.batchId }</li>
                <li>Record ID: { currentBallot.recordId }</li>
            </ul>
            <div>
                Please ensure that the paper ballot you are examining is the
                same ballot type/ID.
            </div>
            <div className='pt-card'>
                <div>
                    Record here the <strong> voter intent </strong> as described by the Voter
                    Intent Guide from the Secretary of State. All markings <strong> do not </strong>
                    need to be recorded. Replicate on this page all <strong> valid votes </strong> in
                    each ballot contest contained on this paper ballot. Or, in case of an
                    <strong> overvote</strong>, record all final voter choices that contribute to
                    the overvote. Please include notes in the comments field.
                </div>
                <MenuDivider />
                <BallotNotFoundForm
                    ballotNotFound={ ballotNotFound }
                    currentBallot={ currentBallot } />
            </div>
        </div>
    </div>
);

const ContestInfo = ({ contest }: any) => {
    const { name, description, choices, votesAllowed } = contest;

    return (
        <div className='pt-card'>
            <div>{ name }</div>
            <div>{ description }</div>
            <div>Vote for { votesAllowed } out of { choices.length }</div>
        </div>
    );
};

const ContestChoices = (props: any) => {
    const { choices, marks, noConsensus, updateBallotMarks } = props;

    const updateChoiceByName = (name: string) => (e: any) => {
        const checkbox = e.target;

        updateBallotMarks({ choices: { [name]: checkbox.checked } });
    };

    const choiceForms = _.map(choices, (choice: any) => {
        const checked = (marks.choices || {})[choice.name];

        return (
            <Checkbox
                key={ choice.name }
                disabled={ noConsensus }
                checked={ checked || false }
                onChange={ updateChoiceByName(choice.name) }
                label={ choice.name }
            />
        );
    });

    return (
        <div className='pt-card'>
            { choiceForms }
        </div>
    );
};

const ContestComments = ({ comments, onChange }: any) => {
    return (
        <div className='pt-card'>
            <label>
                Comments:
                <EditableText multiline value={ comments || '' } onChange={ onChange } />
            </label>
        </div>
    );
};

const BallotContestMarkForm = (props: any) => {
    const { contest, county, currentBallot, updateBallotMarks } = props;
    const { name, description, choices, votesAllowed } = contest;

    const acvr = ((county.acvrs || {})[currentBallot.id]) || {};
    const contestMarks = acvr[contest.id] || {};

    const updateComments = (comments: any) => {
        updateBallotMarks({ comments });
    };

    const updateConsensus = (e: any) => {
        updateBallotMarks({ noConsensus: !!e.target.checked });
    };

    return (
        <div className='pt-card'>
            <ContestInfo contest={ contest } />
            <ContestChoices
                choices={ choices }
                marks={ contestMarks }
                noConsensus={ !!contestMarks.noConsensus }
                updateBallotMarks={ updateBallotMarks }
            />
            <div className='pt-card'>
                <Checkbox
                    label='No consensus'
                    checked={ !!contestMarks.noConsensus }
                    onChange={ updateConsensus }
                />
            </div>
            <ContestComments comments={ contestMarks.comments } onChange={ updateComments } />
        </div>
    );
};

const BallotAuditForm = (props: any) => {
    const { county, currentBallot } = props;

    const contestForms = _.map(currentBallot.contestInfo, (info: any) => {
        const contest = county.contestDefs[info.contest];

        const updateBallotMarks: any = (data: any) => props.updateBallotMarks({
            ballotId: currentBallot.id,
            contestId: contest.id,
            ...data,
        });

        return (
            <BallotContestMarkForm
                key={ contest.id }
                contest={ contest }
                county={ county }
                currentBallot={ currentBallot }
                updateBallotMarks={ updateBallotMarks } />
        );
    });

    return <div>{ contestForms }</div>;
};

const BallotAuditStage = (props: any) => {
    const {
        county,
        nextStage,
        prevStage,
        updateBallotMarks,
    } = props;

    const { ballotsToAudit, ballotUnderAuditId, currentBallot } = county;

    if (ballotUnderAuditId !== currentBallot.id) {
        countyFetchCvr(ballotUnderAuditId);
    }

    const notFound = () => {
        ballotNotFound(currentBallot.id);
    };

    return (
        <div>
            <h2>Ballot verification</h2>
            <AuditInstructions
                ballotNotFound={ notFound }
                ballotsToAudit={ ballotsToAudit }
                currentBallot={ currentBallot }
            />
            <BallotAuditForm
                county={ county }
                currentBallot={ currentBallot }
                updateBallotMarks={ updateBallotMarks }
            />
            <BackButton back={ prevStage } />
            <button className='pt-button pt-intent-primary' onClick={ nextStage }>
                Review
            </button>
        </div>
    );
};


export default BallotAuditStage;
