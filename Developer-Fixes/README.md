We inspected the open-source GitHub repositories that contain smart contracts to identify the developer patches for fixing vulnerabilities.

Repo Selection Criteria
===
- Contains Ethereum smart contracts written in Solidity version >= 0.4.19
- It either has >= 10 stars or >= 10 watchers

Files
===


Repos.csv
---
A list of repos inspected. This includes all inspected repos meeting the above criteria, even if they don't contain patches to vulnerabilities.

### Columns (In order)
1. `RepoName`
2. `#Stars`
3. `#Watchers`
4. `InspectionTime`
5. `LastActivityTime`
6. `#ContractFiles`

#### Note
1. `LastActivityTime` is the latest time among the lastest issue/commit/pull request times
2. `#ContractFiles` is the number of files with file extension `.sol`, this number includes files using unsupported Solidity version.

Patches.csv
---
A list of pull requests and/or commits in their default branch that contains patches to vulnerabilities.

### Columns (In order)
1. `RepoName`
2. `PRID`
3. `IssueIDs`
4. `Commits`
5. `Merged`
6. `ContractName`
7. `FunctionName`
8. `ContractFilePath`
9. `Vulnerabilities`

#### Note
1. PR stands for Pull Request, `PRID` is the ID of the PR.
2. `IssueIDs` is a semi-column separated list of issue IDs related to the PR or commits.
3. `Commits` is a semi-column separated list of full commit hashes appear in the default branch.
4. `Merged` has value `True` or `False`.
5. `ContractName` is the semi-column separated list of names of contracts that were vulnerable and then fixed.
6. `Vulnerabilities` is a semi-column separated list. Each entry is of form `DETECTORS:VULS` where `DETECTORS` is a vertical bar (`|`) separated list of detectors asserting that the set of vulnerabilities in the vertical bar separated list `VULS` are repaired. Each vulnerability in `VULS` is of the form `NAME(LOCS)`, e.g. `Reentrancy(25|26:11|12)`. `LOCS` is a column (`:`) separated list of locations `LOC` while the `LOC` is a vertical bar (`|`) separated list of line numbers. If the detector doesn't provide any location information for the detected vulnerabilities, we use `null` as the `LOCS`.

Contracts.csv
---
A list of contracts identified in the inspected repos.

### Columns (In order)
1. `RepoName`
2. `ContractName`
3. `CommitHashes`
4. `ContractFilePath`
5. `DeploymentAddress`
6. `SOLC-Version`
7. `Vulnerabilities`

#### Note
1. `CommitHashes` is any one of the commits or all commits(separated by semi-column) contain the deployed version of the contract
2. `SOLC-Version` is a semi-column separated list of `solc` versions that we have employed to successfully compile the contract
3. `Vulnerabilities` is a semi-column separated list. Each entry is of format `DETECTOR:VULS` where `DETECTOR` is the detector used and `VULS` is a vertical bar (`|`) separated list of vulnerabilities found by `DETECTOR`. We use `Manual` as the `DETECTOR` when it is manually identified.

Scripts
---
Folder contains all scripts used to generate this dataset.

Logs
---
This contains key logs produced by commands and scripts when creating the data. It contains a README.md to explain the source of the log files committed.

### Logs/Detector

Contains a set of subfolders having the name of detector employed. In each subfolder, name the logs using the contract information and has a `README.md` to explain the naming and the version/environment information of the detector used.
