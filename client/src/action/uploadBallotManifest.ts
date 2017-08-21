import { Dispatch } from 'redux';

import { endpoint } from '../config';


const uploadBallotManifest = (countyId: number, file: Blob, hash: string) => {
    return (dispatch: Dispatch<any>) => {
        dispatch({ type: 'UPLOAD_BALLOT_MANIFEST_SEND' });

        const url = endpoint('upload-ballot-manifest');

        const formData = new FormData();
        formData.append('county', `${countyId}`);
        formData.append('bmi_file', file);
        formData.append('hash', hash);

        const init: any = {
            body: formData,
            credentials: 'include',
            method: 'post',
        };

        fetch(url, init)
            .then(r => {
                if (r.ok) {
                    const sent = { countyId, file, hash };

                    dispatch({ type: 'UPLOAD_BALLOT_MANIFEST_OK', sent });
                } else {
                    dispatch({ type: 'UPLOAD_BALLOT_MANIFEST_FAIL' });
                }
            })
            .catch(() => {
                dispatch({ type: 'UPLOAD_BALLOT_MANIFEST_NETWORK_FAIL' });
            });
    };
};


export default uploadBallotManifest;