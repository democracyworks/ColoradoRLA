# Changes

Releases correspond to Git tags. Changes between releases are described below
with the following tags indicating the components affected:

- `UI` refers the user interface
- `API` refers to the server component
- `INFRA` refers to infrastructure changes such as Docker, HTTPD configuration,
  etc.
- `TOOLING` refers to changes to tooling that falls outside the UI or API, such
  as the RLA export.

## 2.3.9 - Bugfix release
- [UI - Fix contest and choice standardization][pr176]

## 2.3.8 - Bugfix release
- Fix timing bug in standardization process

## 2.3.7 - Bugfix release
- Make standardization process more robust
- Fix unchecked list index access during report generation
- Fix CVR export indicator not correctly showing up

## 2.3.6 - Bugfix release
- [API - allow report to run before any audit submissions][pr165]
- [API - Affirmation text on the county report has more room][pr167]
- [UI - Prevent choice and contest names from growing too long][pr168]
- [API - Allow spaces in canonical choice names][pr169]
- [UI - Remove spinners on CVR upload error][pr170]
- [API - fix weird issue in reports where there are no contestCVRIds][pr171]
- [UI - Update DoS dashboard to handle multiple audit boards][pr173]
- [API - don't set auditStatus if hand counting][pr174]

## 2.3.5 - Bugfix release
- [UI - Immediately show deleted files on the DOS dashboard][pr161]
- [API - Ensure BMI and CVR deletions are reflected in the ASM][pr162]
- [API - Ensure contests are deleted][pr163]

## 2.3.4 - Bugfix release
- [UI - style updates][pr154]
- [UI - Fix slow-to-appear upload spinner][pr157]
- [UI - indicate upload in progress rather than an error][pr158]
- [API - Delete file as the state][pr159]
- [API - fast contest delete][pr160]

## 2.3.3 - Bugfix release
- [API - Throw error on invalid ballot manifests][pr149]
- [API - Fix infinite round loop under certain circumstances][pr152]

## 2.3.2 - Bugfix release
- [UI - simple change to remove warning about breadcrumbs][pr142]
- [UI - Add two new statuses to the state dashboard][pr143]
- [UI - Result on cdb][pr144]
- [UI - Remove manifest and CVR export matcher][pr145]
- [API - update reports sql using uf.computed\_hash][pr146]
- [UI - spinner for delete file][pr147]
- [UI - Re-style file download widget][pr148]

## 2.3.1 - Bugfix release
- [API - add equals to Result][pr141] - fixes concurrent update bug 

## 2.3.0 - New Features
- [UI - UI Refresh][pr137] - new look and feel on login and on the state dashboard
- [API - File fails][pr139] - file upload failures show better error messages
- API - Improved CVR import performance

## 2.2.1 - Bugfix release
- [UI - Remove audit detail section from the county dashboard][pr136]
- [API - fix previously audited showing up in final review page][pr138]

## 2.2.0 - New Features
- [UI - Upgrade to React 16 and BlueprintJS v2][pr134]
- [API - New Reports and a full package download][pr132]

## 2.1.2 - Bugfix release
- [API - fix end of round bug][pr128]

## 2.1.0 - New Features
- [API|UI - Canonical Choices][pr126]
- [API|UI - Re-audit ballots][pr117]

## 2.0.13 - New Features
- [API - Add delete file button][pr110]

## 2.0.12 - Bugfix release
- [UI - Hand count button requires confirmation][pr109]
- [UI - hide submit until valid seed entered][pr108]
- [API - Make the hand count button safe to use][pr107]
- [API - Don't show negative numbers of estimated samples][pr106]

## 2.0.11 - Bugfix release

- [INFRA - smoketest to use python3][cma60b5]
- [API - some debug logging removed][cm506cf]
- [UI - update instruction text][pr101]
- [UI - Fix bad audit board regex that caught just a single digit][pr100]

## 2.0.10 - Bugfix release

- [API - Correctly identify overvotes submitted by an audit board][pr97]
- [API - Database host should be configurable][pr98]

## 2.0.9 - Bugfix release

- [API - Contests that are NOT_AUDITABLE don't impede progress][pr93]

## 2.0.8 - Bugfix release

- [API - change meaning of ballotsRemainingInCurrentRound][pr88]
- [INFRA - add dashboard polling load test script][pr89]
- [UI - Prevent text selection on audit buttons][pr90]

## 2.0.7 - Bugfix release

- [API - Multi-winner contests consider the right margins][pr85]
- [API - Normalize contest choices][pr86]

## 2.0.6 - Bugfix release

- [API - A county with no work must still sign off before the next round][pr83]

## 2.0.5 - Bugfix release

- [API - Adjust where discrepancies appear in the DoS dashboard][pr80]
- [UI - Add CDOS contact info][pr81]
- [UI - Remove 'Vote for X' text from data entry and review screens][pr78]
- [API - Show signatories from all rounds on the affirmation sheet][pr79]
- [API - select CVRs in bulk, add uri concept for fast selection][pr77]

## 2.0.4 - Bugfix release
- [API - Specify column types for map serialization][pr74]
- [API - Show all audit board members on the affirmation sheet][pr73]

## 2.0.3 - Bugfix release

- [API - Only counts selections for the contest we care about][pr70]

## 2.0.2 - Bugfix release

- [API - When a county runs out of ballots, we can only terminate single county audits ][pr66]
- [API - (phantom-record) add ballotType to State report][pr68]

## 2.0.1 - Bugfix release

- [API - A CVR counts as an audited sample if it was selected for an audit][pr61]
- [UI - Fix ballot count pluralization on the county dashboard][pr62]
- [UI - Move "next card" button on the review screen][pr63]
- [UI - Only require no-consensus consent if we are checking the box][pr64]

## 2.0.0 - Major Release

This release contained significant API-level and application-level changes, and
represents over six weeks of sustained development effort.

- [API - Log on phantom CVR creation][pr33]
- [UI - Fix a bug where standardized contests would sometimes not display on first run][pr34]
- [INFRA - Always pull new base Docker images when building][pr35]
- [TOOLING - Better debugging for smoketest main.py][pr36]
- [API - Handle phantom records][pr40]
- [TOOLING - Generate test files for RLAtool][pr42]

The bulk of the changes since the last release are wrapped up in the following
PR:

- [**Support multiple audit boards and multi-county audits**][pr44]

## 1.3.4 - Bugfixes

- [UI - Using MIME type is unreliable][pr29]

## 1.3.3 - Bugfixes

The sprint beginning on 7/18/2018 and ending on 7/31/2018

Fixes bugs from 1.3.0 and 1.3.2 releases

- unauditable contests becoming auditable
- large decimal in risk limit display
- fixed issue where no canonical contests file is uploaded
- removed 0 from range of random numbers

## 1.3.2 - New Features

The sprint beginning on 7/18/2018 and ending on 7/31/2018

- Random ballot selection is driven by ballot manifests (#23) see the
  [wiki](https://github.com/democracyworks/ColoradoRLA/wiki/Random-Number-flow)
  for details. Some attributes still come from the CVR data(imprintedID for
  one). We hope to change that in the future.
- Add support for standardizing contest names (#24 and #25)


## 1.3.1 - Bugfixes

- [API - Fix the "freeze" bug preventing Alamosa from completing their audit](https://github.com/democracyworks/ColoradoRLA/pull/17)
- [UI - Challenge response separates coordinates](https://github.com/democracyworks/ColoradoRLA/pull/18)

## 1.3.0

This represents the two sprints beginning on 6/19/2018 and ending on 7/17/2018
- [Documentation Updates][pr15]
- [UI - Lowercase username parameter to login2F][pr13]
- [remove parameter name constraint][pr11]
- [INFRA - Add support for running in virtual environments][pr10]
- [UI/API - Incorporate CDOS changes][pr9] made between 2017 F&F delivery and Colorado's 2017 General Election
- [UI - All audit info editable][pr8]
- [UI - Add selected contests to review page][pr5]
- [UI - Use a single input field for 2FA challenge][pr4]
- [UI - Usernames need to be lowercase][pr3]
- [API - Ballot Manifest can use strings for Batch IDs][pr2]
- [API - Ballot Manifest objects store their effective start / end sequence numbers][pr1]

## 1.1.0.3

This is [FreeAndFair's most recent tag][1.1.0.3].

[1.1.0.3]: https://github.com/FreeAndFair/ColoradoRLA/tree/v1.1.0.3
[fork]: https://github.com/FreeAndFair/ColoradoRLA/commit/fbbc9aba46c4db4b9c7349a855397a27439d2a5b
[first-commit]: https://github.com/democracyworks/ColoradoRLA/commit/6ce7a45540ccad35ddef85bb38b3fd31d11368ad
[pr1]: https://github.com/democracyworks/ColoradoRLA/pull/1
[pr2]: https://github.com/democracyworks/ColoradoRLA/pull/2
[pr3]: https://github.com/democracyworks/ColoradoRLA/pull/3
[pr4]: https://github.com/democracyworks/ColoradoRLA/pull/4
[pr5]: https://github.com/democracyworks/ColoradoRLA/pull/5
[pr8]: https://github.com/democracyworks/ColoradoRLA/pull/8
[pr9]: https://github.com/democracyworks/ColoradoRLA/pull/9
[pr10]: https://github.com/democracyworks/ColoradoRLA/pull/10
[pr11]: https://github.com/democracyworks/ColoradoRLA/pull/11
[pr13]: https://github.com/democracyworks/ColoradoRLA/pull/13
[pr15]: https://github.com/democracyworks/ColoradoRLA/pull/15
[pr29]: https://github.com/democracyworks/ColoradoRLA/pull/29
[pr33]: https://github.com/democracyworks/ColoradoRLA/pull/33
[pr34]: https://github.com/democracyworks/ColoradoRLA/pull/34
[pr35]: https://github.com/democracyworks/ColoradoRLA/pull/35
[pr36]: https://github.com/democracyworks/ColoradoRLA/pull/36
[pr40]: https://github.com/democracyworks/ColoradoRLA/pull/40
[pr42]: https://github.com/democracyworks/ColoradoRLA/pull/42
[pr44]: https://github.com/democracyworks/ColoradoRLA/pull/44
[pr61]: https://github.com/democracyworks/ColoradoRLA/pull/61
[pr62]: https://github.com/democracyworks/ColoradoRLA/pull/62
[pr63]: https://github.com/democracyworks/ColoradoRLA/pull/63
[pr64]: https://github.com/democracyworks/ColoradoRLA/pull/64
[pr66]: https://github.com/democracyworks/ColoradoRLA/pull/66
[pr68]: https://github.com/democracyworks/ColoradoRLA/pull/68
[pr70]: https://github.com/democracyworks/ColoradoRLA/pull/70
[pr73]: https://github.com/democracyworks/ColoradoRLA/pull/73
[pr74]: https://github.com/democracyworks/ColoradoRLA/pull/74
[pr77]: https://github.com/democracyworks/ColoradoRLA/pull/77
[pr78]: https://github.com/democracyworks/ColoradoRLA/pull/78
[pr79]: https://github.com/democracyworks/ColoradoRLA/pull/79
[pr80]: https://github.com/democracyworks/ColoradoRLA/pull/80
[pr81]: https://github.com/democracyworks/ColoradoRLA/pull/81
[pr83]: https://github.com/democracyworks/ColoradoRLA/pull/83
[pr85]: https://github.com/democracyworks/ColoradoRLA/pull/85
[pr86]: https://github.com/democracyworks/ColoradoRLA/pull/86
[pr88]: https://github.com/democracyworks/ColoradoRLA/pull/88
[pr89]: https://github.com/democracyworks/ColoradoRLA/pull/89
[pr90]: https://github.com/democracyworks/ColoradoRLA/pull/90
[pr93]: https://github.com/democracyworks/ColoradoRLA/pull/93
[pr97]: https://github.com/democracyworks/ColoradoRLA/pull/97
[pr98]: https://github.com/democracyworks/ColoradoRLA/pull/98
[pr100]: https://github.com/democracyworks/ColoradoRLA/pull/100
[pr101]: https://github.com/democracyworks/ColoradoRLA/pull/101
[cm506cf]: https://github.com/democracyworks/ColoradoRLA/commit/506cf568901ce6f1ba8e2085369444d88f802ff6
[cma60b5]: https://github.com/democracyworks/ColoradoRLA/commit/a60b5972b9f6b1a68d4b22cf06721dd41e5a7374
[pr106]: https://github.com/democracyworks/ColoradoRLA/pull/106
[pr107]: https://github.com/democracyworks/ColoradoRLA/pull/107
[pr108]: https://github.com/democracyworks/ColoradoRLA/pull/108
[pr109]: https://github.com/democracyworks/ColoradoRLA/pull/109
[pr110]: https://github.com/democracyworks/ColoradoRLA/pull/110
[pr117]: https://github.com/democracyworks/ColoradoRLA/pull/117
[pr126]: https://github.com/democracyworks/ColoradoRLA/pull/126
[pr128]: https://github.com/democracyworks/ColoradoRLA/pull/128
[pr132]: https://github.com/democracyworks/ColoradoRLA/pull/132
[pr134]: https://github.com/democracyworks/ColoradoRLA/pull/134
[pr136]: https://github.com/democracyworks/ColoradoRLA/pull/136
[pr137]: https://github.com/democracyworks/ColoradoRLA/pull/137
[pr138]: https://github.com/democracyworks/ColoradoRLA/pull/138
[pr139]: https://github.com/democracyworks/ColoradoRLA/pull/139
[pr141]: https://github.com/democracyworks/ColoradoRLA/pull/141
[pr142]: https://github.com/democracyworks/ColoradoRLA/pull/142
[pr143]: https://github.com/democracyworks/ColoradoRLA/pull/143
[pr144]: https://github.com/democracyworks/ColoradoRLA/pull/144
[pr145]: https://github.com/democracyworks/ColoradoRLA/pull/145
[pr146]: https://github.com/democracyworks/ColoradoRLA/pull/146
[pr147]: https://github.com/democracyworks/ColoradoRLA/pull/147
[pr148]: https://github.com/democracyworks/ColoradoRLA/pull/148
[pr149]: https://github.com/democracyworks/ColoradoRLA/pull/149
[pr152]: https://github.com/democracyworks/ColoradoRLA/pull/152
[pr154]: https://github.com/democracyworks/ColoradoRLA/pull/154
[pr157]: https://github.com/democracyworks/ColoradoRLA/pull/157
[pr158]: https://github.com/democracyworks/ColoradoRLA/pull/158
[pr159]: https://github.com/democracyworks/ColoradoRLA/pull/159
[pr160]: https://github.com/democracyworks/ColoradoRLA/pull/160
[pr161]: https://github.com/democracyworks/ColoradoRLA/pull/161
[pr162]: https://github.com/democracyworks/ColoradoRLA/pull/162
[pr163]: https://github.com/democracyworks/ColoradoRLA/pull/163
[pr165]: https://github.com/democracyworks/ColoradoRLA/pull/165
[pr167]: https://github.com/democracyworks/ColoradoRLA/pull/167
[pr168]: https://github.com/democracyworks/ColoradoRLA/pull/168
[pr169]: https://github.com/democracyworks/ColoradoRLA/pull/169
[pr170]: https://github.com/democracyworks/ColoradoRLA/pull/170
[pr171]: https://github.com/democracyworks/ColoradoRLA/pull/171
[pr173]: https://github.com/democracyworks/ColoradoRLA/pull/173
[pr174]: https://github.com/democracyworks/ColoradoRLA/pull/174
[pr176]: https://github.com/democracyworks/ColoradoRLA/pull/176
