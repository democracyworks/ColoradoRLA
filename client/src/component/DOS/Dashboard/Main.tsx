import * as React from 'react';

import RoundContainer from './RoundContainer';

import fetchReport from 'corla/action/dos/fetchReport';

import { endpoint } from 'corla/config';

interface RiskLimitInfoProps {
    riskLimit: number;
}

const RiskLimitInfo = ({ riskLimit }: RiskLimitInfoProps) => {
    return (
        <div className='pt-card'>
            <strong>Target Risk Limit: </strong> { riskLimit * 100 } %
        </div>
    );
};

interface SeedInfoProps {
    seed: string;
}

const SeedInfo = ({ seed }: SeedInfoProps) => {
    return (
        <div className='pt-card'>
            <strong>Seed: </strong> { seed }
        </div>
    );
};

interface DefinitionProps {
    dosState: DOS.AppState;
}

const Definition = ({ dosState }: DefinitionProps) => {
    // We assume this component is only rendered if the audit is defined.
    // If the audit is defined, then we have a `seed`. The compiler can't infer this
    // yet, so we assert it for now.
    return (
        <div>
            <RiskLimitInfo riskLimit={ dosState.riskLimit! } />
            <SeedInfo seed={ dosState.seed! } />
        </div>
    );
};

const NotDefined = () => {
    return (
        <div><h3>The audit has not yet been defined.</h3></div>
    );
};

function activityAllReportUrl() {
    return endpoint('publish-audit-report')
         + '?reportType=activity-all'
         + '&contentType=xlsx';
}

function resultsAllReportUrl() {
    return endpoint('publish-audit-report')
         + '?reportType=results-all'
         + '&contentType=xlsx';
}

interface MainProps {
    auditDefined: boolean;
    canRenderReport: boolean;
    dosState: DOS.AppState;
}

const Main = (props: MainProps) => {
    const { auditDefined, canRenderReport, dosState } = props;

    const auditDefinition = auditDefined
                          ? <Definition dosState={ dosState } />
                          : <NotDefined />;

    if (!dosState.asm) {
        return null;
    }

    if (dosState.asm === 'DOS_AUDIT_COMPLETE') {
        return (
            <div className='sos-notifications pt-card'>
                { auditDefinition }
                <div className='pt-card'>
                <div className='pt-ui-text-large'>Congratulations! The audit is complete.</div>
                </div>
                <div className='pt-card'>
                    <div className='pt-ui-text-large'>Click to download final audit report.</div>
                    <button
                        className='pt-button pt-intent-primary'
                        onClick={ fetchReport }>
                        Download
                    </button>
                    <span>&nbsp;|&nbsp;</span>
                    <a className='pt-button pt-intent-primary'
                       href={ activityAllReportUrl() }>
                        Activity Report
                    </a>
                    <span>&nbsp;|&nbsp;</span>
                    <a className='pt-button pt-intent-primary'
                       target="_blank"
                       href={ resultsAllReportUrl() }>
                        Audit Results Report (new)
                    </a>
                </div>
            </div>
        );
    }

    return (
        <div className='sos-notifications pt-card'>
            { auditDefinition }
            <RoundContainer />
            <div className='pt-card'>
                <div className='pt-ui-text-large'>Download intermediate reports</div>
                <button
                    className='pt-button pt-intent-primary'
                    disabled={ !canRenderReport }
                    onClick={ fetchReport }>
                    Audit Report (old)
                </button>
                <span>&nbsp;|&nbsp;</span>
                <a className='pt-button pt-intent-primary'
                   href={ activityAllReportUrl() }>
                    Activity Report
                </a>
                <span>&nbsp;|&nbsp;</span>
                <a className='pt-button pt-intent-primary'
                   target="_blank"
                   href={ resultsAllReportUrl() }>
                    Audit Results Report (new)
                </a>
            </div>

        </div>
    );
};


export default Main;
