import * as React from 'react';

import { Button, Callout, Intent, Popover } from '@blueprintjs/core';

import downloadFile from 'corla/action/downloadFile';

interface UploadedFileProps {
    description: string;
    file: UploadedFile | undefined | null;
}

const UploadedFile = ({ description, file }: UploadedFileProps) => {
    if (null === file || undefined === file) {
        return (
            <div className='uploaded-file mt-default'>
                <h4>{ description }</h4>
                <p>Not yet uploaded</p>
            </div>
        );
    } else {

        const onClick = () => downloadFile(file.id);

        const downloadButton = (
            <div className='uploaded-file-footer-action'>
                <Button intent={ Intent.PRIMARY }
                        onClick={ onClick }>
                    Download
                </Button>
            </div>);

        const successCard = (
            <Callout className='uploaded-file-footer'>
                <Callout className='uploaded-file-footer-status'
                         intent={ Intent.SUCCESS }
                         icon='tick-circle'>
                    File successfully uploaded
                </Callout>
                { downloadButton }
            </Callout>
        );

        const errorCard = (
            <Callout className='uploaded-file-footer'>
                <Callout className='uploaded-file-footer-status'
                         intent={ Intent.DANGER }
                         icon='error'>
                    <p>
                        <strong>Error: </strong>
                        { file.result.errorMessage ? file.result.errorMessage : 'unknown' }
                        { file.result.errorRowNum &&
                          <Popover className='uploaded-file-popover-target'
                                   popoverClassName='uploaded-file-popover'>
                              <span>at row { file.result.errorRowNum }</span>
                              <div>
                                  <h4>Row { file.result.errorRowNum }</h4>
                                  <p>The content of row { file.result.errorRowNum } is displayed below:</p>
                                  <pre>{ file.result.errorRowContent }</pre>
                              </div>
                          </Popover>
                        }
                    </p>
                </Callout>
                { downloadButton }
            </Callout>
        );

        const pendingCard = (
            <Callout className='uploaded-file-footer'>
                <Callout className='uploaded-file-footer-status'
                         intent={ Intent.WARNING }
                         icon='tick-circle'>
                    File upload in progress...
                </Callout>
            </Callout>
        );

        const resultCard = () => {
            // this behavior lines up with ImportFileController.java
            if (file.result.success === true) {
                return successCard;
                /* if result.success === undefined would be nice, but is */
                /* prevented by the GSON during db storage which sets null to false */
                /* this is a cheap way to infer pending */
            } else if (file.result.errorMessage === undefined) {
                return pendingCard;
            } else {
                return errorCard;
            }
        };

        return (
            <div className='uploaded-file mt-default'>
                <h4>{ description }</h4>
                <dl className='uploaded-file-details'>
                    <dt>File name</dt>
                    <dd>{ file.fileName }</dd>

                    <dt>SHA-256 hash</dt>
                    <dd>{ file.hash }</dd>
                </dl>
                { resultCard() }
            </div>
        );
    }
};

interface DownloadButtonsProps {
    status: County.AppState | DOS.CountyStatus;
}

const FileDownloadButtons = (props: DownloadButtonsProps) => {
    const { status } = props;

    if (!status) {
        return <div />;
    }

    const { ballotManifest, cvrExport } = status;

    return (
        <div className='mt-default'>
            <UploadedFile description='Ballot Manifest' file={ ballotManifest } />
            <UploadedFile description='CVR Export' file={ cvrExport } />
        </div>
    );
};

export default FileDownloadButtons;
