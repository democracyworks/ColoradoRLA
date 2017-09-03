import { takeLatest } from 'redux-saga/effects';

import countyDashboardRefresh from 'corla/action/countyDashboardRefresh';


function* uploadAcvrOk(): any {
    countyDashboardRefresh();
}

export default function* uploadAcvrOkSaga() {
    yield takeLatest('UPLOAD_ACVR_OK', uploadAcvrOk);
}
