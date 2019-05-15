import * as _ from 'lodash';

function capitalize(s: string) {
    if (!s) { return ''; }

    const [fst, ...rest] = s.split('');

    return fst.toUpperCase() + rest.join('');
}

export function electionType(type: ElectionType): string {
    return `${capitalize(type)} Election`;
}

export function formatCountyASMState(state: County.ASMState): string {
    switch (state) {
    case 'COUNTY_INITIAL_STATE':
        return 'Not started';
    case 'BALLOT_MANIFEST_OK':
        return 'Ballot manifest imported';
    case 'CVRS_IMPORTING':
        return 'Importing CVRs';
    case 'CVRS_OK':
        return 'CVRs imported';
    case 'BALLOT_MANIFEST_OK_AND_CVRS_IMPORTING':
        return 'Ballot manifest imported, importing CVRs';
    case 'BALLOT_MANIFEST_AND_CVRS_OK':
        return 'Ballot manifest and CVRs imported';
    case 'COUNTY_AUDIT_UNDERWAY':
        return 'Audit underway';
    case 'COUNTY_AUDIT_COMPLETE':
        return 'Audit complete';
    case 'DEADLINE_MISSED':
        return 'File upload deadline missed';
    }
}

export function formatCountyAndBoardASMState(countyStatus: DOS.CountyStatus): string {
    const countyAsmState = countyStatus.asmState;
    const boardAsmState = countyStatus.auditBoardASMState;

    switch (countyAsmState) {
    case 'COUNTY_AUDIT_UNDERWAY': {
        switch (boardAsmState) {
        case 'AUDIT_INITIAL_STATE':
            // Should not be reachable, given county state.
            return '—';
        case 'WAITING_FOR_ROUND_START':
        case 'WAITING_FOR_ROUND_START_NO_AUDIT_BOARD':
            if (countyStatus.auditBoardCount) {
                return 'Audit board # is set';
            } else {
                return 'Waiting for round start';
            }
        case 'ROUND_IN_PROGRESS':
            return 'Round in progress';
        case 'ROUND_IN_PROGRESS_NO_AUDIT_BOARD':
            if (countyStatus.auditBoardCount) {
                return 'Audit board # is set';
            } else {
                return 'Round in progress';
            }
        case 'WAITING_FOR_ROUND_SIGN_OFF':
        case 'WAITING_FOR_ROUND_SIGN_OFF_NO_AUDIT_BOARD':
            return 'Waiting for round sign-off';
        case 'AUDIT_COMPLETE':
            // Should not be reachable, given county state.
            return 'Audit complete';
        case 'UNABLE_TO_AUDIT':
            // Should not be reachable, given county state.
            return 'Unable to audit';
        case 'AUDIT_ABORTED':
            // Should not be reachable, given county state.
            return '—';
        default:
            // We have branched on every audit board ASM state, but
            // the TypeScript compiler fails to detect this, emitting
            // a spurious error "TS7029: Fallthrough case in switch".
            return '—';
        }
    }
    default:
        if (_.get(countyStatus, 'ballotManifest.result.success') === false ||
            _.get(countyStatus, 'cvrExport.result.success') === false) {
            return 'File upload failed';
        } else {
            return formatCountyASMState(countyAsmState);
        }
    }
}

/*
 * Return the CSS class to display an indicator for a given status.
 */
export function formatCountyAndBoardASMStateIndicator(countyStatus: DOS.CountyStatus): string {
    const countyAsmState = countyStatus.asmState;
    const boardAsmState = countyStatus.auditBoardASMState;

    switch (countyAsmState) {
    case 'COUNTY_AUDIT_UNDERWAY': {
        switch (boardAsmState) {
        case 'ROUND_IN_PROGRESS':
            return 'status-indicator-in-progress';
        default:
            return '';
        }
    }
    default:
        if (_.get(countyStatus, 'ballotManifest.result.success') === false ||
            _.get(countyStatus, 'cvrExport.result.success') === false) {
            return 'status-indicator-error';
        } else {
            return '';
        }
    }
}
