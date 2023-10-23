FORMAT: 1A
HOST: https://api.snyk.io/v1

# Snyk API

The Snyk API is available to customers on [Business and Enterprise plans](https://snyk.io/plans) and allows you to programatically integrate with Snyk.


## REST API
We are in the process of building a new, improved API (`https://api.snyk.io/rest`) built using the OpenAPI and JSON API standards. We welcome you to try it out as we shape and release endpoints until it, ultimately, becomes a full replacement for our current API.

Looking for our REST API docs? Please head over to [https://apidocs.snyk.io](https://apidocs.snyk.io)

## API vs CLI vs Snyk integration
The API detailed below has the ability to test a package for issues, as they are defined by Snyk. It is important to note that for many package managers, using this API will be less accurate than running the [Snyk CLI](https://snyk.io/docs/using-snyk) as part of your build pipe, or just using it locally on your package. The reason for this is that more than one package version fit the requirements given in manifest files. Running the CLI locally tests the actual deployed code, and has an accurate snapshot of the dependency versions in use, while the API can only infer it, with inferior accuracy. It should be noted that the Snyk CLI has the ability to output machine-readable JSON output (with the `--json` flag to `snyk test`).

A third option, is to allow Snyk access to your development flow via the existing [Snyk integrations](https://snyk.io/docs/). The advantage to this approach is having Snyk monitor every new pull request, and suggest fixes by opening new pull requests. This can be achieved either by integrating Snyk directly to your source code management (SCM) tool, or via a broker to allow greater security and auditability.

If those are not viable options, this API is your best choice.

## API url
The base URL for all API endpoints is https://api.snyk.io/v1/

## Authorization
To use this API, you must get your token from Snyk. It can be seen on https://snyk.io/account/ after you register with Snyk and login.

The token should be supplied in an `Authorization` header with the token, preceded by `token`:


```http
Authorization: token API_KEY
```

Otherwise, a 401 "Unauthorized" response will be returned.
```http
HTTP/1.1 401 Unauthorized

        {
            "code": 401,
            "error": "Not authorised",
            "message": "Not authorised"
        }
```


## Overview and entities
The API is a REST API. It has the following entities:

### Test result
The test result is the object returned from the API giving the results of testing a package for issues. It has the following fields:

| Property        | Type    | Description                                           | Example                                                         |
|----------------:|---------|-------------------------------------------------------|-----------------------------------------------------------------|
| ok              | boolean | Does this package have one or more issues?             | false                                                           |
| issues          | object  | The issues found. See below for details.              | See below                                                       |
| dependencyCount | number  | The number of dependencies the package has.           | 9                                                               |
| org             | object  | The organization this test was carried out for.       | {"name": "anOrg", "id": "5d7013d9-2a57-4c89-993c-0304d960193c"} |
| licensesPolicy  | object  | The organization's licenses policy used for this test | See in the examples                                             |
| packageManager  | string  | The package manager for this package                  | "maven"                                                         |
|                 |         |                                                       |                                                                 |


### Issue
An issue is either a vulnerability or a license issue, according to the organization's policy. It has the following fields:

| Property       | Type          | Description                                                                                                                | Example                                |
|---------------:|---------------|----------------------------------------------------------------------------------------------------------------------------|----------------------------------------|
| id             | string        | The issue ID                                                                                                               | "SNYK-JS-BACKBONE-10054"               |
| url            | string        | A link to the issue details on snyk.io                                                                                     | "https://snyk.io/vuln/SNYK-JS-BACKBONE-10054 |
| title          | string        | The issue title                                                                                                            | "Cross Site Scripting"                 |
| type           | string        | The issue type: "license" or "vulnerability".                                                                              | "license"                              |
| paths          | array         | The paths to the dependencies which have an issue, and their corresponding upgrade path (if an upgrade is available). [More information about from and upgrade paths](#introduction/overview-and-entities/from-and-upgrade-paths) | [<br>&nbsp;&nbsp;{<br>&nbsp;&nbsp;&nbsp;&nbsp;"from": ["a@1.0.0", "b@4.8.1"],<br>&nbsp;&nbsp;&nbsp;&nbsp;"upgrade": [false, "b@4.8.2"]<br>&nbsp;&nbsp;}<br>] |
| package        | string        | The package identifier according to its package manager                                                                    | "backbone", "org.apache.flex.blazeds:blazeds"|
| version        | string        | The package version this issue is applicable to.                                                                           | "0.4.0"                                |
| severity       | string        | The Snyk defined severity level: "critical", "high", "medium" or "low".                                                    | "high"                                 |
| language       | string        | The package's programming language                                                                                         | "js"                                   |
| packageManager | string        | The package manager                                                                                                        | "npm"                                  |
| semver         | array[string] OR map[string]array[string] | One or more [semver](https://semver.org) ranges this issue is applicable to. The format varies according to package manager. | ["<0.5.0, >=0.4.0", "<0.3.8, >=0.3.6"] OR { "vulnerable": ["[2.0.0, 3.0.0)"], "unaffected": ["[1, 2)", "[3, )"] } |


### Vulnerability
A vulnerability in a package. In addition to all the fields present in an issue, a vulnerability also has these fields:

 Property        | Type    | Description                                                                                                                                                                                                                      | Example                                        |
----------------:|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
 publicationTime | Date    | The vulnerability publication time                                                                                                                                                                                               | "2016-02-11T07:16:18.857Z"                     |
 disclosureTime  | Date    | The time this vulnerability was originally disclosed to the package maintainers                                                                                                                                                   | "2016-02-11T07:16:18.857Z"                     |
 isUpgradable    | boolean | Is this vulnerability fixable by upgrading a dependency?                                                                                                                                                                         | true                                           |
 description     | string  | The detailed description of the vulnerability, why and how it is exploitable. Provided in markdown format. | "## Overview\n[`org.apache.logging.log4j:log4j-core`](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22log4j-core%22)\nIn Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.\n\n# Details\nSerialization is a process of converting an object into a sequence of bytes which can be persisted to a disk or database or can be sent through streams. The reverse process of creating object from sequence of bytes is called deserialization. Serialization is commonly used for communication (sharing objects between multiple hosts) and persistence (store the object state in a file or a database). It is an integral part of popular protocols like _Remote Method Invocation (RMI)_, _Java Management Extension (JMX)_, _Java Messaging System (JMS)_, _Action Message Format (AMF)_, _Java Server Faces (JSF) ViewState_, etc.\n\n_Deserialization of untrusted data_ ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), is when the application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, letting the attacker to control the state or the flow of the execution. \n\nJava deserialization issues have been known for years. However, interest in the issue intensified greatly in 2015, when classes that could be abused to achieve remote code execution were found in a [popular library (Apache Commons Collection)](https://snyk.io/vuln/SNYK-JAVA-COMMONSCOLLECTIONS-30078). These classes were used in zero-days affecting IBM WebSphere, Oracle WebLogic and many other products.\n\nAn attacker just needs to identify a piece of software that has both a vulnerable class on its path, and performs deserialization on untrusted data. Then all they need to do is send the payload into the deserializer, getting the command executed.\n\n> Developers put too much trust in Java Object Serialization. Some even de-serialize objects pre-authentication. When deserializing an Object in Java you typically cast it to an expected type, and therefore Java's strict type system will ensure you only get valid object trees. Unfortunately, by the time the type checking happens, platform code has already created and executed significant logic. So, before the final type is checked a lot of code is executed from the readObject() methods of various objects, all of which is out of the developer's control. By combining the readObject() methods of various classes which are available on the classpath of the vulnerable application an attacker can execute functions (including calling Runtime.exec() to execute local OS commands).\n- Apache Blog\n\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5645)\n- [jira issue](https://issues.apache.org/jira/browse/LOG4J2-1863)\n" |
 isPatchable     | boolean | Is this vulnerability fixable by using a Snyk supplied patch?                                                                                                                                                                    | true                                           |
 isPinnable      | boolean | Is this vulnerability fixable by pinning a transitive dependency                                                                                                                                                                 | true                                           |
 identifiers     | object  | Additional vulnerability identifiers                                                                                                                                                                                             | {"CWE": [], "CVE": ["CVE-2016-2402]}           |
 credit          | string  | The reporter of the vulnerability                                                                                                                                                                                                | "Snyk Security Team"                           |
 CVSSv3          | string  | Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score. | "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" |
 cvssScore       | number  | CVSS Score                                                                                                                                                                                                                       | 5.3                                            |
 patches         | array   | Patches to fix this issue, by snyk                                                                                                                                                                                               | see "Patch" below.                             |
 upgradePath     | object  | The path to upgrade this issue, if applicable                                                                                                                                                                                    | see below                                      |
 isPatched       | boolean | Is this vulnerability patched?                                                                                                                                                                                                   | false                                          |
 exploitMaturity | string  | The snyk exploit maturity level


#### Patch
A patch is an object like this one:
```json
{
  "urls": [
    "https://snyk-patches.s3.amazonaws.com/npm/backbone/20110701/backbone_20110701_0_0_0cdc525961d3fa98e810ffae6bcc8e3838e36d93.patch"
  ],
  "version": "<0.5.0 >=0.3.3",
  "modificationTime": "2015-11-06T02:09:36.180Z",
  "comments": [
    "https://github.com/jashkenas/backbone/commit/0cdc525961d3fa98e810ffae6bcc8e3838e36d93.patch"
  ],
  "id": "patch:npm:backbone:20110701:0"
}
```

### From and upgrade paths
Both from and upgrade paths are arrays, where each item within the array is a package `name@version`.

Take the following `from` path:
```
[
  "my-project@1.0.0",
  "actionpack@4.2.5",
  "rack@1.6.4"
]
```
Assuming this was returned as a result of a test, then we know:
- The package that was tested was `my-project@1.0.0`
- The dependency with an issue was included in the tested package via the direct dependency `actionpack@4.2.5`
- The dependency with an issue was [rack@1.6.4](https://snyk.io/vuln/rubygems:rack@1.6.4)

Take the following `upgrade` path:
```
[
  false,
  "actionpack@5.0.0",
  "rack@2.0.1"
]
```
Assuming this was returned as a result of a test, then we know:
- The package that was tested is not upgradable (`false`)
- The direct dependency `actionpack` should be upgraded to at least version `5.0.0` in order to fix the issue
- Upgrading `actionpack` to version `5.0.0` will cause `rack` to be installed at version `2.0.1`

If the `upgrade` path comes back as an empty array (`[]`) then this means that there is no upgrade path available which would fix the issue.

### License issue
A license issue has no additional fields other than the ones in "Issue".

### Snyk organization
The organization in Snyk this request is applicable to. The organization determines the access rights, licenses policy and is the unit of billing for private projects.

A Snyk organization has these fields:

Property    | Type   | Description                   | Example                                |
-----------:| ------ | ----------------------------- | -------------------------------------- |
name        | string | The organization display name | "deelmaker"                            |
id          | string | The ID of the organization    | "3ab0f8d3-b17d-4953-ab6d-e1cbfe1df385" |

## Errors
This is a beta release of this API. Therefore, despite our efforts, errors might occur. In the unlikely event of such an error, it will have the following structure as JSON in the body:

Property    | Type   | Description                   | Example                                |
-----------:| ------ | ----------------------------- | -------------------------------------- |
message     | string | Error message with reference  | Error calling Snyk api (reference: 39db46b1-ad57-47e6-a87d-e34f6968030b) |
errorRef    | V4 uuid | An error ref to contact Snyk with | 39db46b1-ad57-47e6-a87d-e34f6968030b |

The error reference will also be supplied in the `x-error-reference` header in the server reply.

Example response:
```http
HTTP/1.1 500 Internal Server Error
x-error-reference: a45ec9c1-065b-4f7b-baf8-dbd1552ffc9f
Content-Type: application/json; charset=utf-8
Content-Length: 1848
Vary: Accept-Encoding
Date: Sun, 10 Sep 2017 06:48:40 GMT
```

## Rate Limiting

To ensure resilience against increasing request rates, we are starting to introduce rate-limiting.
We are monitoring the rate-limiting system to ensure minimal impact on users while ensuring system stability.
The limit is up to 2000 requests per minute, per user, subject to change. As such, we recommend calls to the API are throttled regardless of the current limit.
All requests above the limit will get a response with status code `429` - `Too many requests` until requests stop for the duration of the rate-limiting interval (currently a minute).

## Consuming Webhooks

Webhooks are delivered with a `Content-Type` of `application/json`, with the event payload as JSON in the request body. We also send the following headers:

- `X-Snyk-Event` - the name of the event
- `X-Snyk-Transport-ID` - a GUID to identify this delivery
- `X-Snyk-Timestamp` - an ISO 8601 timestamp for when the event occurred, for example: `2020-09-25T15:27:53Z`
- `X-Hub-Signature` - the HMAC hex digest of the request body, used to secure your webhooks and ensure the request did indeed come from Snyk
- `User-Agent` - identifies the origin of the request, for example: `Snyk-Webhooks/XXX`

---

After your server is configured to receive payloads, it listens for any payload sent to the endpoint you configured. For security reasons, you should limit requests to those coming from Snyk.

### Validating payloads

All transports sent to your webhooks have a `X-Hub-Signature` header, which contains the hash signature for the transport. The signature is a HMAC hexdigest of the request body, generated using sha256 and your `secret` as the HMAC key.

You could use a function in Node.JS such as the following to validate these signatures on incoming requests from Snyk:

```javascript
import * as crypto from 'crypto';

function verifySignature(request, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  const buffer = JSON.stringify(request.body);
  hmac.update(buffer, 'utf8');

  const signature = `sha256=${hmac.digest('hex')}`;

  return signature === request.headers['x-hub-signature'];
}
```

### Payload versioning

Payloads may evolve over time, and so are versioned. Payload versions are supplied as a suffix to the `X-Snyk-Event` header. For example, `project_snapshot/v0` indicates that the payload is `v0` of the `project_snapshot` event.

Version numbers only increment when a breaking change is made; for example, removing a field that used to exist, or changing the name of a field. Version numbers do not increment when making an additive change, such as adding a new field that never existed before.

**Note:** During the BETA phase, the structure of webhook payloads may change at any time, so we  recommend you check the payload version.

### Event types

While consuming a webhook event, `X-Snyk-Event` header must be checked, as an end-point may receive multiple event types.

#### ping

The ping event happens after a new webhook is created, and can also be manually triggered using the ping webhook API. This is useful to test that your webhook receives data from Snyk correctly.

The `ping` event makes the following request:

```jsx
POST /webhook-handler/snyk123 HTTP/1.1
Host: my.app.com
X-Snyk-Event: ping/v0
X-Snyk-Transport-ID: 998fe884-18a0-45db-8ae0-e379eea3bc0a
X-Snyk-Timestamp: 2020-09-25T15:27:53Z
X-Hub-Signature: sha256=7d38cdd689735b008b3c702edd92eea23791c5f6
User-Agent: Snyk-Webhooks/044aadd
Content-Type: application/json
{
  "webhookId": "d3cf26b3-2d77-497b-bce2-23b33cc15362"
}
```

#### project_snapshot

This event is triggered every time an existing project is tested and a new snapshot is created. It is triggered on every test of a project, whether or not there are new issues. This event is not triggered when a new project is created or imported. Currently supported targets/scan types are Open Source and container. 

```jsx
POST /webhook-handler/snyk123 HTTP/1.1
Host: my.app.com
X-Snyk-Event: project_snapshot/v0
X-Snyk-Transport-ID: 998fe884-18a0-45db-8ae0-e379eea3bc0a
X-Snyk-Timestamp: 2020-09-25T15:27:53Z
X-Hub-Signature: sha256=7d38cdd689735b008b3c702edd92eea23791c5f6
User-Agent: Snyk-Webhooks/044aadd
Content-Type: application/json
{
  "project": { ... }, // project object matching API responses
  "org": { ... }, // organization object matching API responses
  "group": { ... }, // group object matching API responses
  "newIssues": [], // array of issues object matching API responses
  "removedIssues": [], // array of issues object matching API responses
}
```

####  Detailed example of a payload

##### project

see: [https://snyk.docs.apiary.io/#reference/projects](https://snyk.docs.apiary.io/#reference/projects)

```tsx
"project": {
  "name": "snyk/goof",
  "id": "af137b96-6966-46c1-826b-2e79ac49bbd9",
  "created": "2018-10-29T09:50:54.014Z",
  "origin": "github",
  "type": "maven",
  "readOnly": false,
  "testFrequency": "daily",
  "totalDependencies": 42,
  "issueCountsBySeverity": {
    "low": 13,
    "medium": 8,
    "high": 4,
    "critical": 5
  },
  "imageId": "sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019",
  "imageTag": "latest",
  "imageBaseImage": "alpine:3",
  "imagePlatform": "linux/arm64",
  "imageCluster": "Production",
  "hostname": null,
  "remoteRepoUrl": "https://github.com/snyk/goof.git",
  "lastTestedDate": "2019-02-05T08:54:07.704Z",
  "browseUrl": "https://app.snyk.io/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/af137b96-6966-46c1-826b-2e79ac49bbd9",
  "importingUser": {
    "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
    "name": "example-user@snyk.io",
    "username": "exampleUser",
    "email": "example-user@snyk.io"
  },
  "isMonitored": false,
  "branch": null,
  "targetReference": null,
  "tags": [
    {
      "key": "example-tag-key",
      "value": "example-tag-value"
    }
  ],
  "attributes": {
    "criticality": [
      "high"
    ],
    "environment": [
      "backend"
    ],
    "lifecycle": [
      "development"
    ]
  },
  "remediation": {
    "upgrade": {},
    "patch": {},
    "pin": {}
  }
}
```

##### org

see: [https://snyk.docs.apiary.io/#reference/organizations](https://snyk.docs.apiary.io/#reference/organizations)

```tsx
"org": {
  "name": "My Org",
  "id": "a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
  "slug": "my-org",
  "url": "https://api.snyk.io/org/my-org",
  "created": "2020-11-18T10:39:00.983Z"
}
```

##### group

see: [https://snyk.docs.apiary.io/#reference/groups](https://snyk.docs.apiary.io/#reference/groups)

```tsx
"group": {
  "name": "ACME Inc.",
   "id": "a060a49f-636e-480f-9e14-38e773b2a97f"
}
```

##### issue

see: https://snyk.docs.apiary.io/#reference/users/user-organization-notification-settings/list-all-aggregated-issues

```tsx
{
  "id": "npm:ms:20170412",
  "issueType": "vuln",
  "pkgName": "ms",
  "pkgVersions": [
    "1.0.0"
  ],
  "issueData": {
    "id": "npm:ms:20170412",
    "title": "Regular Expression Denial of Service (ReDoS)",
    "severity": "low",
    "url": "https://snyk.io/vuln/npm:ms:20170412",
    "description": "Lorem ipsum",
    "identifiers": {
      "CVE": [],
      "CWE": [
        "CWE-400"
      ],
      "ALTERNATIVE": [
        "SNYK-JS-MS-10509"
      ]
    },
    "credit": [
      "Snyk Security Research Team"
    ],
    "exploitMaturity": "no-known-exploit",
    "semver": {
      "vulnerable": [
        ">=0.7.1 <2.0.0"
      ]
    },
    "publicationTime": "2017-05-15T06:02:45Z",
    "disclosureTime": "2017-04-11T21:00:00Z",
    "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cvssScore": 3.7,
    "language": "js",
    "patches": [
      {
        "id": "patch:npm:ms:20170412:2",
        "urls": [
          "https://snyk-patches.s3.amazonaws.com/npm/ms/20170412/ms_071.patch"
        ],
        "version": "=0.7.1",
        "comments": [],
        "modificationTime": "2019-12-03T11:40:45.866206Z"
      }
    ],
    "nearestFixedInVersion": "2.0.0"
  },
  "isPatched": false,
  "isIgnored": false,
  "fixInfo": {
    "isUpgradable": false,
    "isPinnable": false,
    "isPatchable": true,
    "nearestFixedInVersion": "2.0.0"
  },
  "priority": {
    "score": 399,
    "factors": [
      {
        "name": "isFixable",
        "description": "Has a fix available"
      },
      {
        "name": "cvssScore",
        "description": "CVSS 3.7"
      }
    ]
  }
}
```
# Group Users
For more information users and different user types see [Snyk docs](https://docs.snyk.io/introducing-snyk/snyks-core-concepts/groups-organizations-and-users#user-access-member-types).

## User Details [/user/{userId}]
Retrieves information about a user.

### Get User Details [GET]
+ Parameters
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The users ID. The `API_KEY` must have admin access to at least one group or organization where the requested user is a member and must have the `api` entitlement on their preferred organization.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + id (string) - The id of the user.
        + name (string) - The name of the user.
        + username (string) - The username of the user.
        + email (string) - The email of the user.

+ Response 400 (application/json; charset=utf-8)
The provided `id` is not in a valid format.
    + Body

            {}

+ Response 401 (application/json; charset=utf-8)
`API_KEY` is invalid.
    + Body

            {}

+ Response 404 (application/json; charset=utf-8)
The requested user could not be found or caller does not have sufficient permissions.
    + Body

            {}

## My User Details [/user/me]
Retrieves information about the the user making the request.

### Get My Details [GET]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + id (string) - The id of the user.
        + username (string) - The username of the user.
        + email (string) - The email of the user.
        + orgs (array) - The organizations that the user belongs to.

+ Response 401 (application/json; charset=utf-8)
`API_KEY` is invalid.
    + Body

            {}

## User organization notification settings [/user/me/notification-settings/org/{orgId}]
The organization notification settings for the user that will determine which emails are sent.

### Get organization notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification settings response)


### Modify organization notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification settings request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification settings response)

## User project notification settings [/user/me/notification-settings/org/{orgId}/project/{projectId}]
The project notification settings for the user that will determine which emails are sent.

### Get project notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return notification settings for.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification settings response)

### Modify project notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY
    + Attributes
        + `new-issues-remediations` (New issues notification setting request)

+ Response 200 (application/json; charset=utf-8)
# Group Groups
Groups can contain multiple organizations, allowing you to collaborate with multiple teams. For more information on Groups, organizations, and users see [Snyk docs](https://docs.snyk.io/introducing-snyk/snyks-core-concepts/groups-organizations-and-users).

## Group settings [/group/{groupId}/settings]
+ Parameters
    + groupId: `b61bc07c-27c6-42b3-8b04-0f228ed31a67` (string, required) - The group ID. The `API_KEY` must have admin access to this group.

### View group settings [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY
+ Response 200 (application/json; charset=utf-8)
    + Attributes (Group settings)
    + Body

            {
                "sessionLength": null,
                "requestAccess": {
                    "enabled": true,
                }
            }

### Update group settings [PUT]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY
    + Attributes (Group settings)
    + Body

            {
                "sessionLength": 50,
                 "requestAccess": {
                    "enabled": true,
                }
            }

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Group settings)
    + Body

            {
                "sessionLength": 50,
                 "requestAccess": {
                    "enabled": true,
                }
            }

## Organizations in a group [/group/{groupId}/org]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access to this group.


## List members in a group [/group/{groupId}/members]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.

### List all members in a group [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (array)
        + (object)
            + id (string) - The id of the user.
            + name (string) - The name of the user.
            + username (string) - The username of the user.
            + email (string) - The email of the user (email is null if the member is a service account).
            + orgs (array)
                + (object)
                    + name (string) - The name of the organization
                    + role (string) - the role of the user in the organization
            + groupRole (string) - (Optional) The role of the user in the group.

## Members in an organization of a group [/group/{groupId}/org/{orgId}/members]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID we want to add the member to. The `API_KEY` must have access to this organization.

### Add a member to an organization within a group [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Add member body)

+ Response 200 (application/json; charset=utf-8)

## List all tags in a group [/group/{groupId}/tags{?perPage,page}]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.
    + perPage: `10` (number, optional) - The number of results to return (the default is 1000).
    + page: `1` (number, optional) - The offset from which to start returning results from.

### List all tags in a group [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Headers

            Link: <https://api.snyk.io/v1/group/4a18d42f-0706-4ad0-b127-24078731fbed/tags?page=3&perPage=10>; rel=last, <https://api.snyk.io/v1/group/4a18d42f-0706-4ad0-b127-24078731fbed/tags?page=2&perPage=10>; rel=next

    + Attributes
        + tags (array)
            + (Tag body)

    + Body

            {
                "tags": [
                    {
                        "key": "meta",
                        "value": "Alfa"
                    },
                    {
                        "key": "meta",
                        "value": "Bravo"
                    },
                    {
                        "key": "meta",
                        "value": "Charlie"
                    },
                    {
                        "key": "meta",
                        "value": "Delta"
                    },
                    {
                        "key": "meta",
                        "value": "Echo"
                    },
                    {
                        "key": "meta",
                        "value": "Foxtrot"
                    },
                    {
                        "key": "meta",
                        "value": "Golf"
                    },
                    {
                        "key": "meta",
                        "value": "Hotel"
                    },
                    {
                        "key": "meta",
                        "value": "India"
                    },
                    {
                        "key": "meta",
                        "value": "Juliet"
                    }
                ]
            }

## Delete Tag From Group [/group/{groupId}/tags/delete]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The group ID. The `API_KEY` must have access admin to this group.

### Delete tag from group [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Delete tag body)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Delete tag body)

## List all organizations in a group [/group/{groupId}/orgs{?perPage,page,name}]
+ Parameters
    + groupId: `a060a49f-636e-480f-9e14-38e773b2a97f` (string, required) - The group ID. The `API_KEY` must have READ access to this group and LIST organizations access in this group.
    + perPage: `100` (number, optional) - The number of results to return (maximum is 100).
        + Default: `100`
    + page: `1` (number, optional) - For pagination - offset (from which to start returning results).
    + name: `my` (string, optional) - Only organizations that have a name that **starts with** this value (case insensitive) will be returned.

### List all organizations in a group  [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
            "id": "a060a49f-636e-480f-9e14-38e773b2a97f",
            "name": "ACME Inc.",
            "url": "https://api.snyk.io/group/0dfc509a-e7a9-48ef-9d39-649d6468fc09",
            "created": "2021-06-07T00:00:00.000Z",
            "orgs":
            [
                {
                    "name":"myDefaultOrg",
                    "id":"689ce7f9-7943-4a71-b704-2ba575f01089",
                    "slug":"my-default-org",
                    "url":"https://api.snyk.io/org/default-org",
                    "created": "2021-06-07T00:00:00.000Z"
                },
                {
                    "name":"My Other Org",
                    "id":"a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
                    "slug":"my-other-org",
                    "url":"https://api.snyk.io/org/my-other-org",
                    "created": "2021-06-07T00:00:00.000Z"
                }
            ]
        }

## List all roles in a group [/group/{groupId}/roles]
+ Parameters
  + groupId: `a060a49f-636e-480f-9e14-38e773b2a97f` (string, required) - The group ID. The `API_KEY` must have READ access to this group.

### List all roles in a group [GET]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        [{
            "name": "Org Collaborator",
            "description": "Collaborator",
            "publicId": "6525b356-a400-465f-b2e5-3eee1161e69f",
            "created": "2021-04-22T16:02:53.233Z",
            "modified": "2021-04-22T16:02:53.332Z"
        },
        {
            "name": "Org Admin",
            "description": "Admin",
            "publicId": "af047fef-69f3-4bd9-9760-8957ce0d2ece",
            "created": "2021-04-22T16:02:53.233Z",
            "modified": "2021-04-22T16:02:53.332Z"
        }]

# Data Structures

## Group settings (object)
+ requestAccess (object, optional) - Can only be updated if `API_KEY` has edit access to request access settings.
    + enabled: true (boolean, required) - Choose whether a user may request access to Snyk orgs in this group that they are not a member of.
+ sessionLength (number) - The new session length for the group in minutes. This must be an integer between 1 and 43200 (30 days). Setting this value to null will result in this group inheriting from the global default of 30 days.

## Tag body
  + key (string) - Valid tag key.
  + value (string) - Valid tag value.

## Delete tag body
  + key (string) - Valid tag key.
  + value (string) - Valid tag value.
  + force (boolean) - force delete tag that has entities (default is `false`).

## Add member body
  + userId (string) - The id of the user.
  + role (string) - The role of the user, "admin" or "collaborator".
# Group Organizations
For more information on organizations see [Snyk docs](https://docs.snyk.io/introducing-snyk/snyks-core-concepts/groups-organizations-and-users#snyk-organizations).

## The Snyk organization for a request [/orgs]
Each request to Snyk has to be done in the context of a Snyk organization. If no organization is specified, the user's default organization (user is identified according to the `API_KEY`) will be used.
The organization determines the access rights, licenses policy and is the unit of billing for private projects.

An organization should be given as a query parameter named `org`, with the public identifier given to this org. The list of organizations and their corresponding public ids can be found with the organization resource.


### List all the organizations a user belongs to [GET]
+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
            "orgs": [
                {
                    "name":"defaultOrg",
                    "id":"689ce7f9-7943-4a71-b704-2ba575f01089",
                    "slug":"default-org",
                    "url":"https://api.snyk.io/org/default-org",
                    "group": null
                },
                {
                    "name":"My Other Org",
                    "id":"a04d9cbd-ae6e-44af-b573-0556b0ad4bd2",
                    "slug":"my-other-org",
                    "url":"https://api.snyk.io/org/my-other-org",
                    "group": {
                        "name": "ACME Inc.",
                        "id": "a060a49f-636e-480f-9e14-38e773b2a97f"
                    }
                }
            ]
        }

## Create organization [/org]
An organization can be created as part of a group, or independently. If the **groupId** is not provided, a **Personal Org** will be created independent of a group.

### Create a new organization [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Create organizations body)

+ Response 201 (application/json; charset=utf-8)
    + Body

             {
                "id": "0356f641-c55c-488f-af05-c2122590f369",
                "name": "new-org",
                "slug": "new-org",
                "url": "https://snyk.io/org/new-org",
                "created": "2021-01-07T16:07:16.237Z",
                "group": {
                    "name": "test-group",
                    "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
                }
            }

+ Response 422 (application/json, charset=utf-8)
    A group of errors that show input errors about the parameters provided in the request.

    + Attributes
        + message (string)-  The error message
        + errorRef (string) - [UUID] An error ref to contact Snyk with

    + Body

            {
                "message": "Please provide a new organization name in the body of the request",
                "errorRef": "49f168a0-a084-4cd8-93ff-63f3a0f06bc6"
            }

+ Response 401 (application/json, charset=utf-8)
    Authorization errors.

    + Attributes
        + message (string)-  The error message
        + errorRef (string) - [UUID] An error ref to contact Snyk with

    + Body

            {
                "message": "You must have the required permissions to add an org",
                "errorRef": "49f168a0-a084-4cd8-93ff-63f3a0f06bc6"
            }

+ Response 400 (application/json, charset=utf-8)
    A group of errors that happened in the process of creating a new organization and were unexpected

    + Attributes
        + message (string)-  The error message
        + errorRef (string) - [UUID] An error ref to contact Snyk with

    + Body

            {
                "message": "Unexpected error whilst deleting org",
                "errorRef": "49f168a0-a084-4cd8-93ff-63f3a0f06bc6"
            }


## Notification settings [/org/{orgId}/notification-settings]
Manage the default settings for organization notifications. These will be used as defaults, but can be re-defined by organization members.

### Get organization notification settings [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification settings response)

### Set notification settings [PUT]
+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Edit Organization`
    + Headers

            Authorization: token API_KEY
    + Attributes (Notification settings request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Notification settings response)

## User invitation to organization [/org/{orgId}/invite]
Invite users to the organization by email.

### Invite users [POST]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Users`
        + `Invite Users`
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + email (string) - The email of the user.
        + isAdmin (boolean, optional) - (optional) Set the role as admin.

+ Response 200 (application/json; charset=utf-8)

## Members in organization [/org/{orgId}/members{?includeGroupAdmins}]
Manage members in your organization.

### List Members [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID.
    + includeGroupAdmins: `true` (boolean, optional) - Include group administrators who also have access to this organization.
        + Default: `false`

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Users`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (array)
        + (object)
            + id (string) - The id of the user.
            + name (string) - The name of the user.
            + username (string) - The username of the user.
            + email (string) - The email of the user.
            + role (string) - The role of the user in the organization.

## Organization settings [/org/{orgId}/settings]

### View organization settings [GET]
+ Parameters
    + orgId: `25065eb1-109c-4c3e-9503-68fc56ef6f44` (string, required) - The organization ID. The `API_KEY` must have access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Org settings response)

### Update organization settings [PUT]
Settings that are not provided will not be modified.

+ Parameters
    + orgId: `25065eb1-109c-4c3e-9503-68fc56ef6f44` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Edit Organization`
    + Headers

            Authorization: token API_KEY
    + Attributes (Org settings request)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Org settings response)

+ Response 403 (application/json; charset=utf-8)
If provided a setting that the `API_KEY` has no edit permission for.
    + Attributes ()

## Manage roles in organization [/org/{orgId}/members/{userId}]
Manage member's roles in your organization.

### Update a member in the organization [PUT]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The user ID.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `Manage Users`
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + role (string) - The new role of the user, "admin" or "collaborator".

+ Response 200 (application/json; charset=utf-8)

### Remove a member from the organization [DELETE]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must admin have access to this organization.
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The user ID we want to remove.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Users`
        + `User Remove`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Update member roles in your organization [/org/{orgId}/members/update/{userId}]
Update member's role in your organization by role publicId.

### Update a member's role in the organization [PUT]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + userId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The user ID.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `Manage Users`
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + rolePublicId (string) - The new role public ID to update the user to.

+ Response 200

## Manage organization [/org/{orgId}]

### Remove organization [DELETE]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have permission to delete the provided organization. Currently this operation is only supported for organizations without any projects.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Remove Organization`
    + Headers

            Authorization: token API_KEY

+ Response 204 (application/json; charset=utf-8)

## Provision user [/org/{orgId}/provision]

This endpoint allows Snyk Admins to provision user access to Snyk Orgs prior to the user login to the Snyk platform, and does not send out invitation emails to the Snyk platform. When the provisioned user logs into Snyk for the first time, the user will automatically be granted the appropriate Snyk org access and role permissions specified in the API call. This endpoint can be called multiple times to provision a user to multiple Snyk orgs. The API token used requires Org Admin permisisons, and must be part of a Snyk group with a valid SSO connection.  Service accounts are restricted from invoking this API. As this endpoint can only be used to provision new users, if a user has already logged into Snyk, this endpoint will not work to provision user access.

### Provision a user to the organization [POST]

+ Parameters
    + orgId: `25065eb1-109c-4c3e-9503-68fc56ef6f44` (string, required) - The organization ID. The `API_KEY` must not exceed the permissions being granted to the provisioned user.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `Provision User`
    + Headers

            Authorization: token API_KEY
    + Attributes (object)
        + email (string, required) - The email of the user.
        + rolePublicId (string) - ID of the role to grant this user.
        + role (string) - Deprecated. Name of the role to grant this user. Must be one of `ADMIN`, `COLLABORATOR`, or `RESTRICTED_COLLABORATOR`. This field is invalid if `rolePublicId` is supplied with the request.

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + email (string) - The email of the user.
        + role (string) - Name of the role granted for this user.
        + rolePublicId (string) - ID of the role to granted for this user.
        + created (string) - Timestamp of when this provision record was created.

+ Response 403 (application/json; charset=utf-8)
Provided `API_KEY` has no user provision permission or does not have permissions in role being provisioned.
    + Attributes ()

### List pending user provisions [GET]

+ Parameters
    + orgId: `25065eb1-109c-4c3e-9503-68fc56ef6f44` (string, required) - The organization ID.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `Provision User`
    + Query parameters
        + perPage (number) - Number of items to return
        + page (number) - Page number of the response body
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (array)
        + (object)
            + email (string) - The email of the user.
            + role (string) - Name of the role granted for this user.
            + rolePublicId (string) - ID of the role to granted for this user.
            + created (string) - Timestamp of when this provision record was created.

+ Response 403 (application/json; charset=utf-8)
Provided `API_KEY` has no user provision permission or does not have permissions in role being provisioned.
    + Attributes ()

### Delete pending user provision[DELETE]

+ Parameters
    + orgId: `25065eb1-109c-4c3e-9503-68fc56ef6f44` (string, required) - The organization ID.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `Provision User`
    + Query parameters
        + email (string) - The email of the user.
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + ok (boolean) - Deletion succeeded.

+ Response 403 (application/json; charset=utf-8)
Provided `API_KEY` has no user provision permission or does not have permissions in role being provisioned.
    + Attributes ()

# Data Structures

## Create organizations body
  + name: `new-org` (string, required) - The name of the new organization
  + groupId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, optional) - The group ID. The `API_KEY` must have access to this group.
  + sourceOrgId: `6b4a3261-b68f-43a0-9218-1f082e77f879` (string, optional) - The id of an organization to copy settings from.

  If provided, this organization must be associated with the same group.

  The items that will be copied are: 
    Source control integrations (GitHub, GitLab, BitBucket)
    \+ Container registries integrations (ACR, Docker Hub, ECR, GCR)
    \+ Container orchestrators integrations (Kubernetes)
    \+ PaaS and Serverless Integrations (Heroku, AWS Lambda)
    \+ Notification integrations (Slack, Jira)
    \+ Policies
    \+ Ignore settings
    \+ Language settings
    \+ Infrastructure as Code settings
    \+ Snyk Code settings
    
  The following will not be copied across:
    Service accounts
    \+ Members
    \+ Projects
    \+ Notification preferences
    
    
    
    
    
# Group Integrations
Integrations are connections to places where code lives. They can be configured from the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) page.

## Integrations [/org/{orgId}/integrations]

### List [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization public ID. The `API_KEY` must have admin access to this organization.

+ Request (application/json; charset=utf-8)

    + Required permissions
        + `View Organization`
        + `View Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Integrations body)
    + Body

            {
                "github": "9a3e5d90-b782-468a-a042-9a2073736f0b",
                "gitlab": "1b3e3d90-c678-347a-n232-6a3453738h1e",
                "bitbucket-cloud": "6jje4c92-e7rn-t59a-f456-8n5675432fe9"
            }

### Add new integration [POST]
Add new integration for given organization.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Attributes (object)
        + type (IntegrationType, required) - integration type
        + credentials (IntegrationCredentials, required) - credentials for given integration

    + Headers

            Authorization: token API_KEY

    + Body

            {
                "type": "github",
                "credentials": { "token": "GITHUB_TOKEN" }
            }


+ Response 200 (application/json; charset=utf-8)
    + Body

            {
              "id": "9a3e5d90-b782-468a-a042-9a2073736f0b"
            }

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Attributes (object)
        + type (IntegrationType, required) - integration type
        + broker (BrokerSettings, required) - brokered integration settings

    + Headers

            Authorization: token API_KEY

    + Body

            {
                "type": "bitbucket-server",
                "broker": { "enabled": true }
            }

+ Response 200 (application/json; charset=utf-8)
    + Body

            {
              "id": "9a3e5d90-b782-468a-a042-9a2073736f0b",
              "brokerToken": "4a18d42f-0706-4ad0-b127-24078731fbed"
            }

## Integration [/org/{orgId}/integrations/{integrationId}]

### Update existing integration [PUT]
+ Update integration's credentials for given organization. Integration must be **not brokered**
+ Enable or disable brokered integration for given organization. *Credentials required for disabling brokered integration*

Examples in right section:

1. Set up a broker for an existing integration
2. Update credentials for an existing non-brokered integration
3. Disable broker for an existing integration


+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The unique identifier for the configured integration. This can be found on the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) for all integrations that have been configured.

+ Request Set up a broker for an existing integration (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Attributes (object)
        + type (IntegrationType, required) - integration type
        + broker (BrokerSettings, required) - brokered integration settings

    + Headers

            Authorization: token API_KEY

    + Body

            {
                "type": "github",
                "broker": { "enabled": true }
            }


+ Response 200 (application/json; charset=utf-8)

        {
          "id": "9a3e5d90-b782-468a-a042-9a2073736f0b",
          "brokerToken": "4a18d42f-0706-4ad0-b127-24078731fbed"
        }


+ Request Update credentials for an existing non-brokered integration (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Attributes (object)
        + type (IntegrationType, required) - integration type
        + credentials (IntegrationCredentials, required) - credentials for given integration

    + Headers

            Authorization: token API_KEY

    + Body

            {
                "type": "gitlab",
                "credentials": { "token": "GITLAB_TOKEN" }
            }


+ Response 200 (application/json; charset=utf-8)

        {
          "id": "9a3e5d90-b782-468a-a042-9a2073736f0b"
        }

+ Request Disable broker for an existing integration (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Attributes (object)
        + type (IntegrationType, required) - integration type
        + broker (BrokerSettings, required) - brokered integration settings
        + credentials (IntegrationCredentials, required) - credentials for given integration

    + Headers

            Authorization: token API_KEY

    + Body

            {
                "type": "github",
                "broker": { "enabled": false },
                "credentials": { "token": "GITHUB_TOKEN" }
            }


+ Response 200 (application/json; charset=utf-8)

        {
          "id": "9a3e5d90-b782-468a-a042-9a2073736f0b"
        }

## Integration authentication [/org/{orgId}/integrations/{integrationId}/authentication]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + integrationId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The integration ID.

### Delete credentials [DELETE]

Removes any credentials set for this integration. If this is a brokered connection the operation will have no effect.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Integration broker token provisioning [/org/{orgId}/integrations/{integrationId}/authentication/provision-token]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The `API_KEY` must have access to this organization.
    + integrationId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required)


### Provision new broker token [POST]

Issue a new and unique provisional broker token for the brokered integration.

Used for zero down-time token rotation with the Snyk Broker. Once provisioned, the token can be used to initialize a new broker client before using the switch API to update the token in use by the integration.

The new provisional token will fail to be created if the integration, or any other integration in the same group, already has one provisioned.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

        {
          "id": "9a3e5d90-b782-468a-a042-9a2073736f0b",
          "provisionalBrokerToken": "4a18d42f-0706-4ad0-b127-24078731fbed"
        }

## Integration broker token switching [/org/{orgId}/integrations/{integrationId}/authentication/switch-token]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The `API_KEY` must have access to this organization.
    + integrationId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required)

### Switch between broker tokens [POST]

Switch the existing broker token with the provisioned token for this integration and any other in the same group.
Only perform this action when you have a Broker client running with the provisioned token.
This action will fail if there is no token provisioned for this integration or any integration in the same group.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)


## Integration cloning [/org/{orgId}/integrations/{integrationId}/clone]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - Source organization public ID to clone integration settings from. The `API_KEY` must have access to this organization.
    + integrationId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - Source integration public ID to clone.

### Clone an integration (with settings and credentials)  [POST]

Clone an integration, including all of its settings and credentials from one organization to another organization in the same group.
This API supports both brokered and non-brokered integrations.

Use this API for when you want to share a Broker token between several Snyk organizations (integrations).

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + destinationOrgPublicId (string, required) - The organization public ID. The `API_KEY` must have access to this organization.

    + Body

            {
                "destinationOrgPublicId": "9a3e5d90-b782-468a-a042-9a2073736f0b1"
            }


+ Response 200 (application/json; charset=utf-8)

        {
            "newIntegrationId": "9a3e5d90-b782-468a-a042-9a2073736f0b"
        }

## Integration by type [/org/{orgId}/integrations/{type}]
### Get existing integration by type [GET]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The `API_KEY` must have admin access to this organization.
    + type: `github` (IntegrationType, required) - Integration type.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + id (string) - Alphanumeric UUID including - with a limit of 36 characters
    + Body

            {
              "id": "9a3e5d90-b782-468a-a042-9a2073736f0b"
            }

## Integration settings [/org/{orgId}/integrations/{integrationId}/settings]

### Retrieve [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The unique identifier for the configured integration. This can be found on the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) for all integrations that have been configured.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Integration settings)
    + Body

            {
                "autoDepUpgradeLimit": 1,
                "autoDepUpgradeIgnoredDependencies": [],
                "autoDepUpgradeEnabled": true,
                "autoDepUpgradeMinAge": 21,
                "pullRequestFailOnAnyVulns": true,
                "pullRequestFailOnlyForHighSeverity": true,
                "pullRequestTestEnabled": true,
                "pullRequestAssignment": {
                  "enabled": true,
                  "type": "manual",
                  "assignees": ["username"]
                }
                "autoRemediationPrs": {
                  "backlogPrsEnabled": false,
                  "backlogPrStrategy": "vuln",
                  "freshPrsEnabled": true,
                  "usePatchRemediation": false
                },
                "manualRemediationPrs": {
                    "useManualPatchRemediation": false
                },
                "dockerfileSCMEnabled": true
            }

### Update [PUT]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The unique identifier for the configured integration. This can be found on the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) for all integrations that have been configured.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Integrations`
        + `Edit Integrations`
    + Headers

            Authorization: token API_KEY

    + Attributes (Integration settings)
    + Body

            {
              "autoDepUpgradeLimit": 2,
              "autoDepUpgradeIgnoredDependencies": [],
              "autoDepUpgradeEnabled": false,
              "autoDepUpgradeMinAge": 21,
              "pullRequestTestEnabled": true,
              "pullRequestFailOnAnyVulns": false,
              "pullRequestFailOnlyForHighSeverity": true,
              "pullRequestAssignment": {
                "enabled": true,
                "type": "manual",
                "assignees": ["username"]
              },
              "autoRemediationPrs": {
                "backlogPrsEnabled": false,
                "backlogPrStrategy": "vuln",
                "freshPrsEnabled": true,
                "usePatchRemediation": false
              },
              "manualRemediationPrs": {
                    "useManualPatchRemediation": false
              },
              "dockerfileSCMEnabled": true
            }

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Integration settings)
    + Body

            {
                "autoDepUpgradeLimit": 2,
                "autoDepUpgradeIgnoredDependencies": [],
                "autoDepUpgradeEnabled": false,
                "autoDepUpgradeMinAge": 21,
                "pullRequestTestEnabled": true,
                "pullRequestFailOnAnyVulns": false,
                "pullRequestFailOnlyForHighSeverity": true,
                "pullRequestAssignment": {
                  "enabled": true,
                  "type": "manual",
                  "assignees": ["username"]
                },
                "autoRemediationPrs": {
                  "backlogPrsEnabled": false,
                  "backlogPrStrategy": "vuln",
                  "freshPrsEnabled": true,
                  "usePatchRemediation": false
                },
                "manualRemediationPrs": {
                    "useManualPatchRemediation": false
                },
                "dockerfileSCMEnabled": true
            }

# Data Structures

## Integrations body
    + Attributes (array)
        + (Integrations)

## Integration settings
  + autoDepUpgradeLimit (number, optional) - A limit on how many automatic dependency upgrade PRs can be opened simultaneously
  + autoDepUpgradeIgnoredDependencies (array[string], optional) - A list of strings defining what dependencies should be ignored
  + autoDepUpgradeEnabled (boolean, optional) - Defines if the functionality is enabled
  + autoDepUpgradeMinAge (number, optional) - The age (in days) that an automatic dependency check is valid for
  + pullRequestFailOnAnyVulns (boolean, optional) - If an opened PR should fail to be validated if any vulnerable dependencies have been detected
  + pullRequestFailOnlyForHighSeverity (boolean, optional) - If an opened PR only should fail its validation if any dependencies are marked as being of high severity
  + pullRequestTestEnabled (boolean, optional) - If opened PRs should be tested
  + pullRequestAssignment (PullRequestAssignment, optional) - assign Snyk pull requests
  + autoRemediationPrs (object, optional) - Defines automatic remediation policies
    + backlogPrsEnabled (boolean, optional) - If true, allows automatic remediation of prioritized backlog issues
    + backlogPrStrategy (enum[string]) - Determine which issues are fixed in a backlog PR
      + Members
        + `vuln` - Open a backlog PR to fix the highest priority vulnerability
        + `dependency` - Open a backlog PR to fix all issues in the package with the highest priority vulnerability
    + freshPrsEnabled (boolean, optional) - If true, allows automatic remediation of newly identified issues, or older issues where a fix has been identified
    + usePatchRemediation (boolean, optional) - If true, allows using patched remediation
  + manualRemediationPrs (object, optional) - Defines manual remediation policies
    + usePatchRemediation (boolean, optional) - If true, allows using patched remediation
  + dockerfileSCMEnabled (boolean, optional) - If true, will automatically detect and scan Dockerfiles in your Git repositories, surface base image vulnerabilities and recommend possible fixes

# IntegrationType (enum)
+ `acr`
+ `artifactory-cr`
+ `azure-repos`
+ `bitbucket-cloud`
+ `bitbucket-server`
+ `digitalocean-cr`
+ `docker-hub`
+ `ecr`
+ `gcr`
+ `github`
+ `github-cr`
+ `github-enterprise`
+ `gitlab`
+ `gitlab-cr`
+ `google-artifact-cr`
+ `harbor-cr`
+ `nexus-cr`
+ `quay-cr`

# BrokerSettings (object)
+ enabled (boolean)

# IntegrationCredentials
+ One Of
    + AcrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `name.azurecr.io`
    + ArtifactoryCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `name.jfrog.io`
    + AzureReposCredentials
        + username (string, required)
        + url (string, required)
    + BitbucketCloudCredentials
        + username (string, required)
        + password (string, required)
    + BitbucketServerCredentials
        + username (string, required)
        + password (string, required)
        + url (string, required)
    + DigitalOceanCrCredentials
        + token (string, required) - Personal Access Token
    + DockerHubCredentials
        + username (string, required)
        + password (string, required) - Access Token
    + EcrCredentials
        + region (string, required) - e.g.: `eu-west-3`
        + roleArn (string, required) - e.g.: `arn:aws:iam::<account-id>:role/<newRole>`
    + GcrCredentials
        + password (string, required) - JSON key file
        + registryBase (string, required) - e.g.: `gcr.io`, `us.gcr.io`, `eu.gcr.io`, `asia.gcr.io`
    + GitHubCredentials (object)
        + token (string, required)
    + GitHubCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `ghcr.io`
    + GitHubEnterpriseCredentials
        + token (string, required)
        + url (string, required)
    + GitLabCredentials
        + token (string, required)
        + url (string) - for self-hosted GitLab only
    + GitLabCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `your.gitlab.host`
    + GoogleArtifactCrCredentials
        + password (string, required) - JSON key file
        + registryBase (string, required) - e.g.: `us-east1-docker.pkg.dev`, `europe-west1-docker.pkg.dev`
    + HarborCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `your.harbor.host`
    + NexusCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `your.nexus.host`
    + QuayCrCredentials
        + username (string, required)
        + password (string, required)
        + registryBase (string, required) - e.g.: `quay.io`, `your.quay.host`
# Group Import Projects
Import projects into Snyk. Projects can be Git repositories, Docker images, containers, configuration files and much more. See the [Projects and Targets documentation](https://docs.snyk.io/getting-started/introduction-to-snyk-projects#targets) for more information. A typical import would start with requesting a target to be processed and then polling the Import Job API for further details on completion and resulting Snyk projects.

## Import [/org/{orgId}/integrations/{integrationId}/import]
Request a [target](https://docs.snyk.io/getting-started/introduction-to-snyk-projects#targets) to be analyzed for supported Snyk projects via a configured [integration](https://docs.snyk.io/integrations). See the [Integrations API](https://snyk.docs.apiary.io/#reference/integrations) to configure a new integration.
### Import targets [POST]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The unique identifier for the configured integration. This can be found on the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) for all integrations that have been configured.

+ Request GitHub, GitHub Enterprise and Azure Repos (application/json; charset=utf-8)
Note: Importing targets through a Github (Cloud) integration requires the use of a [Snyk personal access/api token](https://app.snyk.io/account).

    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + owner: `org-security` (string, required) - for Github: account owner of the repository; for Azure Repos, this is `Project ID`
            + name: `goof` (string, required) - name of the repo
            + branch: `main` (string, required) - default branch of the repo (Please contact support if you want to import a non default repo branch)
        + files (array, optional) - an array of file objects
            + (object)
                + path: `example/package.json` (string) - relative path to the file
        + exclusionGlobs (string, optional) - a comma-separated list of up to 10 folder names to exclude from scanning (each folder name must not exceed 100 characters). If not specified, it will default to "fixtures, tests, \\_\\_tests\\_\\_, node_modules". If an empty string is provided - no folders will be excluded. This attribute is only respected with Open Source and Container scan targets.

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request GitLab (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + id: `11` (number, required) - id of the repo
            + branch: `develop` (string, required) - repo branch
        + files (array, optional) - an array of file objects
            + (object)
                + path: `example/package.json` (string) - path to the file
        + exclusionGlobs (string, optional) - a comma-separated list of up to 10 folder names to exclude from scanning. If not specified, it will default to "fixtures, tests, \\_\\_tests\\_\\_, node_modules". If an empty string is provided - no folders will be excluded. This attribute is only respected with Open Source and Container scan targets.

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Bitbucket Cloud and Bitbucket Cloud App (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + owner: `org-security` (string, required) - this is the `Workspace ID`
            + name: `goof` (string, required) - name of the repo
        + files (array, optional) - an array of file objects
            + (object)
                + path: `example/package.json` (string) - relative path to the file
        + exclusionGlobs (string, optional) - a comma-separated list of up to 10 folder names to exclude from scanning (each folder name must not exceed 100 characters). If not specified, it will default to "fixtures, tests, \\_\\_tests\\_\\_, node_modules". If an empty string is provided - no folders will be excluded. This attribute is only respected with Open Source and Container scan targets.

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import


+ Request Bitbucket Server (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + projectKey: `SNYK_REPOS` (string, required) - project key
            + repoSlug: `test` (string, required) - slug of the repo
            + name (string, optional) - custom name for the project
            + branch (string, optional) - target branch name
        + files (array, optional) - an array of file objects
            + (object)
                + path: `example/package.json` (string) - path to the file
        + exclusionGlobs (string, optional) - a comma-separated list of up to 10 folder names to exclude from scanning. If not specified, it will default to "fixtures, tests, \\_\\_tests\\_\\_, node_modules". If an empty string is provided - no folders will be excluded. This attribute is only respected with Open Source and Container scan targets.

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Heroku (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + appId (string, required) - ID of the app
            + slugId (string, required) - ID of the slug
        + files (array, optional) - an array of file objects
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request AWS Lambda (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + functionId (string, required) - ID of the app
        + files (array, optional) - an array of file objects
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request CloudFoundry, Pivotal & IBM Cloud (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + appId (string, required) - ID of the app
        + files (array, optional) - an array of file objects
            + (object)
                + path (string) - path to the file

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Docker Hub (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + name: organization/repository:tag (string, required) - image name including tag prefixed by organization name

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Azure Container Registry, Elastic Container Registry, Artifactory Container Registry, Nexus (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + name: repository:tag (string, required) - image name including tag

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

+ Request Google Container Registry, Google Artifact Registry, Harbor, DigitalOcean Container Registry, Quay, GitLab Container Registry, GitHub Container Registry (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

    + Attributes (object)
        + target (object)
            + name: project/repository:tag (string, required) - image name including tag prefixed by project id or project name

+ Response 201 (application/json; charset=utf-8)
    + Headers

            Location: URL for the status API call of the import

## Import job [/org/{orgId}/integrations/{integrationId}/import/{jobId}]

### Get import job details [GET]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have admin access to this organization.
    + integrationId: `9a3e5d90-b782-468a-a042-9a2073736f0b` (string, required) - The unique identifier for the configured integration. This can be found on the [Integration page in the Settings area](https://app.snyk.io/manage/integrations) for all integrations that have been configured.
    + jobId: `1a325d9d-b782-468a-a242-9a2073734f0b` (string, required) - The ID of the job. This can be found in the Location response header from the corresponding POST request that triggered the import job.

+ Request (application/json; charset=utf-8)
    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + id (string) - A uuid representing the job's id
        + status (string) - a string representing the status of a job.
        One of: pending, failed, aborted or complete.
        + created (string) - the time when an import job was created represented as a [UTC (ISO-8601)](https://tools.ietf.org/html/rfc3339) string
        + logs (array) - all organizations imported by the job
            + (object)
                + name (string) - the name of an organization
                + created (string) - the time when the importing the organization was attempted represented as a [UTC (ISO-8601)](https://tools.ietf.org/html/rfc3339) string
                + status (string) - a string representing the status of the attempted import
                One of: pending, failed, aborted or complete.
                + truncated (boolean, optional) - a flag indicating if the import was truncated
                + projects (array) - projects assigned to the imported organization
                    + (object)
                        + targetFile (string) - the project's package manifest file
                        + success (boolean) - specifies if the project was successfully imported
                        + projectUrl (string) - the URL to the project
                        + projectId (string) - the Snyk project publicId
    + Body

            {
              "id": "dce061f7-ce0f-4ccf-b49b-4335d1205bd9",
              "status": "pending",
              "created": "2018-07-23T15:21:10.611Z",
              "logs": [
                {
                  "name": "org1/repo1",
                  "created": "2018-07-23T15:21:10.643Z",
                  "status": "failed",
                  "projects": []
                },
                {
                  "name": "org2/repo2",
                  "created": "2018-07-23T15:21:10.644Z",
                  "status": "complete",
                  "projects": [
                    {
                      "targetFile": "package.json",
                      "success": true,
                      "projectUrl": "https://snyk.io/org/org-name/project/7eeaee25-5f9b-4d05-8818-4cca2c9d9adc"
                    }
                  ]
                },
                {
                  "name": "org3/repo3",
                  "created": "2018-07-23T15:21:10.643Z",
                  "status": "pending",
                  "projects": [
                    {
                      "targetFile": "package.json",
                      "success": true,
                      "projectUrl": "https://snyk.io/org/org-name/project/0382897c-0617-4429-86df-51187dfd42f6"
                    }
                  ]
                }
              ]
            }
# Group Projects
A project is a package that is actively tracked by Snyk.

## All projects [/org/{orgId}/projects]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list projects for. The `API_KEY` must have access to this organization.

### List all projects [POST]
### Do not continue to use this endpoint as it is deprecated and will be removed December 22nd, 2023.
    In its place, please use the [REST List all projects API](https://apidocs.snyk.io/?version=2023-06-19#get-/orgs/-org_id-/projects).
    For more information, including a migration guide, please see this [notice](https://headwayapp.co/snyk-io-updates/deprecation-and-end-of-life-for-the-list-all-projects-v1-api-267781).
> **Note:**  When importing or updating projects, changes will be reflected on the endpoint results after around a ten-second delay. 

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

    + Attributes (Projects filters)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (List all projects)

    + Body

            {
                "org": {
                    "name": "defaultOrg",
                    "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
                },
                "projects": [
                    {
                        "name": "atokeneduser/goof",
                        "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                        "created": "2018-10-29T09:50:54.014Z",
                        "origin": "cli",
                        "type": "npm",
                        "readOnly": false,
                        "testFrequency": "daily",
                        "totalDependencies": 438,
                        "issueCountsBySeverity": {
                            "low": 8,
                            "medium": 15,
                            "high": 10,
                            "critical": 3
                        },
                        "remoteRepoUrl": "https://github.com/snyk/goof.git",
                        "lastTestedDate": "2019-02-05T06:21:00.000Z",
                        "importingUser": {
                            "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
                            "name": "example-user@snyk.io",
                            "username": "exampleUser",
                            "email": "example-user@snyk.io"
                        },
                        "isMonitored": true,
                        "owner": {
                            "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
                            "name": "example-user@snyk.io",
                            "username": "exampleUser",
                            "email": "example-user@snyk.io"
                        },
                        "branch": "master",
                        "targetReference": "master",
                        "tags": [
                            {
                                "key": "example-tag-key",
                                "value": "example-tag-value"
                            }
                        ]
                    },
                    {
                        "name": "atokeneduser/clojure",
                        "id": "af127b96-6966-46c1-826b-2e79ac49bbd9",
                        "created": "2018-10-29T09:50:54.014Z",
                        "origin": "github",
                        "type": "maven",
                        "readOnly": false,
                        "testFrequency": "daily",
                        "totalDependencies": 42,
                        "issueCountsBySeverity": {
                            "low": 8,
                            "medium": 21,
                            "high": 3,
                            "critical": 10
                        },
                        "remoteRepoUrl": "https://github.com/clojure/clojure.git",
                        "lastTestedDate": "2019-02-05T07:01:00.000Z",
                        "owner": {
                            "id": "42ce0e0f-6288-4874-9266-ef799e7f31bb",
                            "name": "example-user2@snyk.io",
                            "username": "exampleUser2",
                            "email": "example-user2@snyk.io"
                        },
                        "importingUser": {
                            "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
                            "name": "example-user@snyk.io",
                            "username": "exampleUser",
                            "email": "example-user@snyk.io"
                        },
                        "isMonitored": false,
                        "branch": "master",
                        "targetReference": "master",
                         "tags": [
                            {
                                "key": "example-tag-key",
                                "value": "example-tag-value"
                            }
                        ]
                    },
                    {
                        "name": "docker-image|alpine",
                        "id": "f6c8339d-57e1-4d64-90c1-81af0e811f7e",
                        "created": "2019-02-04T08:54:07.704Z",
                        "origin": "cli",
                        "type": "apk",
                        "readOnly": false,
                        "testFrequency": "daily",
                        "totalDependencies": 14,
                        "issueCountsBySeverity": {
                            "low": 0,
                            "medium": 0,
                            "high": 0,
                            "critical": 0
                        },
                        "imageId": "sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019",
                        "imageTag": "latest",
                        "lastTestedDate": "2019-02-05T08:54:07.704Z",
                        "owner": null,
                        "importingUser": null,
                        "isMonitored": false,
                        "branch": "master",
                        "targetReference": "master",
                        "tags": [
                            {
                                "key": "example-tag-key",
                                "value": "example-tag-value"
                            }
                        ]
                    }
                ]
            }

## Individual project [/org/{orgId}/project/{projectId}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID the project belongs to. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID.

### Retrieve a single project [GET]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Project)

### Update a project [PUT]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Edit Project`

    + Headers

            Authorization: token API_KEY - The provided API_KEY must have an admin role on either the organization or the group which the project belongs too.

    + Attributes
        + owner (object, optional) - Set to `null` to remove all ownership. User must be a member of the same organization as the project.
            + id: `1acd4d09-5602-4d04-9640-045fe928aaea` (string) - A user to assign as the project owner.
        + branch: `main` (string, optional) - The branch that this project should be monitoring

    + Body

            {
                "owner": {
                    "id": "1acd4d09-5602-4d04-9640-045fe928aaea"
                },
                "branch": "main"
            }

+ Response 200 (application/json; charset=utf-8)
    + Attributes (Project)

### Delete a project [DELETE]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Remove Project`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Deactivate an individual project [/org/{orgId}/project/{projectId}/deactivate]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID the project belongs to. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID.

### Deactivate [POST]
Deactivating a project will:
- Disable pull request tests for new vulnerabilities.
- Disable Fix pull request from being opened for newly disclosed vulnerabilities.
- Disable recurring tests - email alerts about newly disclosed vulnerabilities will be turned off.
- If the repository has no other active projects, then remove any webhooks related to the project.

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Project Status`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Activate an individual project [/org/{orgId}/project/{projectId}/activate]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID the project belongs to. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID.

### Activate [POST]
Activating a project will:
- Add a repository webhook for supported integrations.
- Enable pull request tests for new vulnerabilities.
- Open Fix pull request for newly disclosed vulnerabilities.
- Enable recurring tests, sending email alerts about newly disclosed vulnerabilities.

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Project Status`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Aggregated Project issues [/org/{orgId}/project/{projectId}/aggregated-issues]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return issues for.

### List all Aggregated issues [POST]
+ Request (application/json)

    + Required permissions
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

    + Attributes (Aggregated project issues filters)

    + Body

            {
                "includeDescription": false,
                "includeIntroducedThrough": false
            }

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Aggregated project issues)

## Project Issue Paths [/org/{orgId}/project/{projectId}/issue/{issueId}/paths{?snapshotId,perPage,page}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID for which to return issue paths.
    + issueId: `SNYK-JS-LODASH-590103` (string, required) - The issue ID for which to return issue paths.
    + snapshotId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454553` (string, optional) - The project snapshot ID for which to return issue paths. If set to `latest`, the most recent snapshot will be used. Use the "List all project snapshots" endpoint to find suitable values for this.
        + Default: latest
    + perPage: `3` (number, optional) - The number of results to return per page (1 - 1000, inclusive).
        + Default: 100
    + page: `2` (number, optional) - The page of results to return.
        + Default: 1

### List all project issue paths [GET]
+ Request (application/json)

    + Required permissions
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Headers

            Link: <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=1&perPage=3>; rel=prev, <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=3&perPage=3>; rel=next, <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=4&perPage=3>; rel=last

    + Attributes (Issue paths)

    + Body

            {
                "snapshotId": "6d5813be-7e6d-4ab8-80c2-1e3e2a454553",
                "paths": [
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-traverse",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                            "fixVersion": "11.1.5"
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-template",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                            "fixVersion": "11.1.6"
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-generator",
                            "version": "6.26.1"
                        },
                        {
                            "name": "babel-types",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                ],
                "total": 10,
                "links": {
                    "prev": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=1&perPage=3",
                    "next": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=3&perPage=3",
                    "last": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/issue/SNYK-JS-LODASH-590103?snapshotId=6d5813be-7e6d-4ab8-80c2-1e3e2a454553&page=4&perPage=3"
                }
            }

## Project History [/org/{orgId}/project/{projectId}/history{?perPage,page}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return snapshots for.
    + perPage: `10` (number, optional) - The number of results to return (the default is 10, the maximum is 100).
    + page: `1` (number, optional) - The offset from which to start returning results from.

### List all project snapshots [POST]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

    + Attributes (Project snapshots filters)

    + Body

            {
                "filters": {
                    "imageId": "sha256:a368cbcfa6789bc347345f6d78902afe138b62ff5373d2aa5f37120277c90a67"
                }
            }

+ Response 200 (application/json; charset=utf-8)
    + Headers

            Link: <https://api.snyk.io/v1/org/2d5c4d0c-c6d6-4658-a703-c2721c135b26/project/84dc70ad-eea9-468d-ae43-f0966ba12c99/history?page=3&perPage=100>; rel=last, <https://api.snyk.io/v1/org/2d5c4d0c-c6d6-4658-a703-c2721c135b26/project/84dc70ad-eea9-468d-ae43-f0966ba12c99/history?page=2&perPage=100>; rel=next

    + Attributes (Project snapshots)

    + Body

            {
                "snapshots": [
                    {
                        "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545",
                        "created": "2019-02-05T06:21:00.000Z",
                        "totalDependencies": 438,
                        "issueCounts": {
                            "vuln": {
                                "low": 8,
                                "medium": 15,
                                "high": 13,
                                "critical": 0
                            },
                            "license": {
                                "low": 8,
                                "medium": 15,
                                "high": 13,
                                "critical": 0
                            }
                        },
                        "imageId": "sha256:a368cbcfa6789bc347345f6d78902afe138b62ff5373d2aa5f37120277c90a67",
                        "imageTag": "latest",
                        "imagePlatform": "linux/amd64",
                        "baseImageName": "fedora:32",
                        "method": "web-test"
                    },
                    {
                        "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454553",
                        "created": "2019-02-04T06:19:00.000Z",
                        "totalDependencies": 438,
                        "issueCounts": {
                            "vuln": {
                                "low": 8,
                                "medium": 15,
                                "high": 13,
                                "critical": 0
                            },
                            "license": {
                                "low": 8,
                                "medium": 15,
                                "high": 13,
                                "critical": 0
                            }
                        },
                        "imageId": "sha256:a368cbcfa6789bc347345f6d78902afe138b62ff5373d2aa5f37120277c90a67",
                        "imageTag": "latest",
                        "imagePlatform": "linux/amd64",
                        "baseImageName": "fedora:32",
                        "method": "web-test"
                    }
                ],
                "total": 2
            }

## Aggregated Project Snapshot Issues [/org/{orgId}/project/{projectId}/history/{snapshotId}/aggregated-issues]
+ Parameters
    + orgId: `2d5c4d0c-c6d6-4658-a703-c2721c135b26` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID.
    + snapshotId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454553` (string, optional) - The snapshot ID. If set to latest, the most recent snapshot will be used.

### List all project snapshot aggregated issues [POST]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

    + Attributes (Aggregated project issues filters)

    + Body

            {
                "includeDescription": false,
                "includeIntroducedThrough": false
            }

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Aggregated project issues)

## Project Snapshot Issue Paths [/org/{orgId}/project/{projectId}/history/{snapshotId}/issue/{issueId}/paths{?perPage,page}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID for which to return issue paths.
    + snapshotId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454553` (string, required) - The project snapshot ID for which to return issue paths. If set to `latest`, the most recent snapshot will be used. Use the "List all project snapshots" endpoint to find suitable values for this.
    + issueId: `SNYK-JS-LODASH-590103` (string, required) - The issue ID for which to return issue paths.
    + perPage: `3` (number, optional) - The number of results to return per page (1 - 1000, inclusive).
        + Default: 100
    + page: `2` (number, optional) - The page of results to return.
        + Default: 1

### List all project snapshot issue paths [GET]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Headers

            Link: <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=1&perPage=3>; rel=prev, <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=3&perPage=3>; rel=next, <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=4&perPage=3>; rel=last

    + Attributes (Issue paths)

    + Body

            {
                "snapshotId": "6d5813be-7e6d-4ab8-80c2-1e3e2a454553",
                "paths": [
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-traverse",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                            "fixVersion": "11.1.5"
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-template",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                    [
                        {
                            "name": "tap",
                            "version": "11.1.5",
                            "fixVersion": "11.1.6"
                        },
                        {
                            "name": "nyc",
                            "version": "11.9.0"
                        },
                        {
                            "name": "istanbul-lib-instrument",
                            "version": "1.10.1"
                        },
                        {
                            "name": "babel-generator",
                            "version": "6.26.1"
                        },
                        {
                            "name": "babel-types",
                            "version": "6.26.0"
                        },
                        {
                            "name": "lodash",
                            "version": "4.17.10"
                        }
                    ],
                ],
                "total": 10,
                "links": {
                    "prev": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=1&perPage=3",
                    "next": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=3&perPage=3",
                    "last": "https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/6d5813be-7e6d-4ab8-80c2-1e3e2a454545/history/6d5813be-7e6d-4ab8-80c2-1e3e2a454553/issue/SNYK-JS-LODASH-590103?page=4&perPage=3"
                }
            }

## Project dependency graph [/org/{orgId}/project/{projectId}/dep-graph]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to return issues for.
### Get Project dependency graph [GET]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    * A reference implementation of the graph, as well as conversion functions to/from legacy tree format, can be found at: https://github.com/snyk/dep-graph.
    * The object might contain additional fields in the future, in a backward-compatible way (`schemaVersion` will change accordingly).

    + Attributes (Project dependency graph)

    + Body

            {
                "depGraph": {
                    "schemaVersion": "1.1.0",
                    "pkgManager": {
                        "name": "npm"
                    },
                    "pkgs": [
                        {
                            "id": "demo-app-for-test@1.1.1",
                            "info": {
                                "name": "demo-app-for-test",
                                "version": "1.1.1"
                            }
                        },
                        {
                            "id": "express@4.4.0",
                            "info": {
                                "name": "express",
                                "version": "4.4.0"
                            }
                        },
                        {
                            "id": "ws@1.0.0",
                            "info": {
                                "name": "ws",
                                "version": "1.0.0"
                            }
                        }
                    ],
                    "graph": {
                        "rootNodeId": "root-node",
                        "nodes": [
                            {
                                "nodeId": "root-node",
                                "pkgId": "demo-app-for-test@1.1.1",
                                "deps": [
                                    {
                                        "nodeId": "express@4.4.0"
                                    },
                                    {
                                        "nodeId": "ws@1.0.0"
                                    }
                                ]
                            },
                            {
                                "nodeId": "express@4.4.0",
                                "pkgId": "express@4.4.0",
                                "deps": []
                            },
                            {
                                "nodeId": "ws@1.0.0",
                                "pkgId": "ws@1.0.0",
                                "deps": []
                            }
                        ]
                    }
                }
            }

## Project ignores [/org/{orgId}/project/{projectId}/ignores]
Ignores from `.snyk` files are not included here.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list ignores for. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to list ignores for.

### List all ignores [GET]
Temporary ignores include an `expires` attribute, while permanent ignores do not.

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Ignores`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (All ignores)

    + Body

            {
                "npm:qs:20140806-1": [
                    {
                        "*": {
                            "reason": "No fix available",
                            "created": "2017-10-31T11:24:00.932Z",
                            "expires": "2017-12-10T15:39:38.099Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "temporary-ignore",
                            "disregardIfFixable": true
                        }
                    }
                ],
                "npm:negotiator:20160616": [
                    {
                        "*": {
                            "reason": "Not vulnerable via this path",
                            "created": "2017-10-31T11:24:45.365Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "not-vulnerable",
                            "disregardIfFixable": false
                        }
                    }
                ],
                "npm:electron:20170426": [
                    {
                        "*": {
                            "reason": "Low impact",
                            "created": "2017-10-31T11:25:17.138Z",
                            "ignoredBy": {
                                "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                                "name": "Joe Bloggs",
                                "email": "jbloggs@gmail.com"
                            },
                            "reasonType": "wont-fix",
                            "disregardIfFixable": false
                        }
                    }
                ]
            }

## Ignored issues [/org/{orgId}/project/{projectId}/ignore/{issueId}]
It is possible to modify/retrieve ignored [vulnerability](https://snyk.docs.apiary.io/#introduction/overview-and-entities/vulnerability) or [license](https://snyk.docs.apiary.io/#introduction/overview-and-entities/license-issue) issues for a given organization and project.
Ignores from `.snyk` files are not included here.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to modify ignores for. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to modify ignores for.
    + issueId: `npm:qs:20140806-1` (string, required) - The issue ID to modify ignores for. Can be a vulnerability or a license Issue.

### Retrieve ignore [GET]
+ Request (application/json)

    + Required permissions
        + `View Project`
        + `View Project Ignores`

    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

    + Attributes (Ignore)

    + Body

            [
                {
                    "*": {
                        "reason": "No fix available",
                        "created": "2017-10-31T11:24:00.932Z",
                        "ignoredBy": {
                            "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                            "name": "Joe Bloggs",
                            "email": "jbloggs@gmail.com"
                        },
                        "reasonType": "temporary-ignore",
                        "disregardIfFixable": true
                    }
                }
            ]

### Add ignore [POST]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project Ignores`
        + `Create new project ignores`

    + Headers

            Authorization: token API_KEY

    + Attributes (Ignore rule)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Ignore)

    + Body

            {
                "*": {
                    "reason": "No fix available",
                    "created": "2017-10-31T11:24:00.932Z",
                    "ignoredBy": {
                        "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                        "name": "Joe Bloggs",
                        "email": "jbloggs@gmail.com"
                    },
                    "reasonType": "temporary-ignore",
                    "disregardIfFixable": true
                }
            }

### Replace ignores [PUT]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project Ignores`
        + `Edit Project Ignores`

    + Headers

            Authorization: token API_KEY

    + Attributes (Ignore rules)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Ignores)

    + Body

            [
                {
                    "*": {
                        "reason": "No fix available",
                        "created": "2017-10-31T11:24:00.932Z",
                        "ignoredBy": {
                            "id": "a3952187-0d8e-45d8-9aa2-036642857b4f",
                            "name": "Joe Bloggs",
                            "email": "jbloggs@gmail.com"
                        },
                        "reasonType": "temporary-ignore",
                        "disregardIfFixable": true
                    }
                }
            ]

### Delete ignores [DELETE]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project Ignores`
        + `Remove Project Ignores`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Project jira issues [/org/{orgId}/project/{projectId}/jira-issues]

If you have configured an integration with Jira, it is possible to create Jira issues for project vulnerabilities or license issues directly from the Snyk API.

The Jira integration is available to customers on the pro or enterprise plan.

At the moment, the usage of the Jira integration via the API is not supported for Snyk Infrastructure as Code.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list Jira issues for. The `API_KEY` must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID to list Jira issues for.

### List all jira issues [GET]
+ Request (application/json)

    + Required permissions
        + `View Jira issues`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

    + Attributes (All jira issues)

    + Body

            {
                "npm:qs:20140806-1": [
                    {
                        "jiraIssue": {
                            "id": "10001",
                            "key": "EX-1",
                        }
                    }
                ],
                "npm:negotiator:20160616": [
                    {
                        "jiraIssue": {
                            "id": "10002",
                            "key": "EX-2",
                        }
                    }
                ]
            }

### Create jira issue [POST /org/{orgId}/project/{projectId}/issue/{issueId}/jira-issue]
+ Parameters
    + issueId: `npm:qs:20140806-1` (string, required) - The issue ID to create Jira issue for.

+ Request (application/json)

    + Required permissions
        + `Create Jira issues`

    + Headers

            Authorization: token API_KEY

    + Attributes (Jira issue request)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Jira issue)

    + Body

            {
                "jiraIssue": {
                    "id": "10001",
                    "key": "EX-1",
                }
            }


## Project settings [/org/{orgId}/project/{projectId}/settings]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to which the project belongs. The API_KEY must have access to this organization.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID

### List project settings [GET]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
The response will contain only attributes that can be updated (see `ATTRIBUTES` section in `Update project settings`) and that have been previously set.

    + Attributes (Project settings)

    + Body

            {
                "autoDepUpgradeLimit": 2,
                "autoDepUpgradeIgnoredDependencies": ["tap", "ava"],
                "autoDepUpgradeEnabled": false,
                "autoDepUpgradeMinAge": 21,
                "pullRequestFailOnAnyVulns": false,
                "pullRequestFailOnlyForHighSeverity": true,
                "pullRequestTestEnabled": true,
                "pullRequestAssignment": {
                  "enabled": true,
                  "type": "manual",
                  "assignees": ["username"]
                },
                "autoRemediationPrs": {
                  "freshPrsEnabled": true,
                  "backlogPrsEnabled": false,
                  "usePatchRemediation": true
                }
            }

### Update project settings [PUT]
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Edit Project`

    + Headers

            Authorization: token API_KEY

    + Attributes (Project settings)

    + Body

            {
                "autoDepUpgradeLimit": 2,
                "autoDepUpgradeIgnoredDependencies": ["tap", "ava"],
                "autoDepUpgradeEnabled": false,
                "autoDepUpgradeMinAge": 21,
                "pullRequestFailOnAnyVulns": false,
                "pullRequestFailOnlyForHighSeverity": true,
                "pullRequestTestEnabled": true,
                "pullRequestAssignment": {
                  "enabled": true,
                  "type": "manual",
                  "assignees": ["username"]
                },
                "autoRemediationPrs": {
                  "freshPrsEnabled": true,
                  "backlogPrsEnabled": false,
                  "usePatchRemediation": false
                }
            }

+ Response 200 (application/json; charset=utf-8)
The response will contain the attributes and values that have been sent in the request and successfully updated.

    + Attributes (Project settings)

    + Body

                {
                    "autoDepUpgradeLimit": 2,
                    "autoDepUpgradeIgnoredDependencies": ["tap", "ava"],
                    "autoDepUpgradeEnabled": false,
                    "autoDepUpgradeMinAge": 21,
                    "pullRequestTestEnabled": true,
                    "pullRequestFailOnAnyVulns": false,
                    "pullRequestFailOnlyForHighSeverity": true,
                    "pullRequestAssignment": {
                      "enabled": true,
                      "type": "manual",
                      "assignees": ["username"]
                    },
                    "autoRemediationPrs": {
                      "freshPrsEnabled": true,
                      "backlogPrsEnabled": false,
                      "usePatchRemediation": false
                    }
                }

### Delete project settings [DELETE]
Deleting project settings will set the project to inherit default settings from its integration.
+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Edit Project`

    + Headers

            Authorization: token API_KEY

+ Response 204 (application/json; charset=utf-8)


## Move project [/org/{orgId}/project/{projectId}/move]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to which the project belongs. The API_KEY must have group admin permissions. If the project is moved to a new group, a personal level API key is needed.
    + projectId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The project ID.

### Move project to a different organization [PUT]

Note: when moving a project to a new organization, the historical data used for reporting does not move with it.

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Move Project`

    + Headers

            Authorization: token API_KEY

    + Attributes (Project move)

    + Body

            {
                "targetOrgId": "4a18d42f-0706-4ad0-b127-24078731fbed"
            }

+ Response 200 (application/json; charset=utf-8)

    + Body

            {
                "originOrg": "4a18d42f-0706-4ad0-b127-24078731fbed",
                "destinationOrg": "4a18d42f-0706-4ad0-b127-24078731fbed",
                "movedProject": "463c1ee5-31bc-428c-b451-b79a3270db08"
            }

## Project tags [/org/{orgId}/project/{projectId}/tags]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to apply the tag to

### Add a tag to a project [POST]
​
+ Request (application/json)

    + Required permissions
        + Group Admin

    + Headers

            Authorization: token API_KEY - The user must have an admin role on either the organization or the group which the project belongs too. If the tag hasn't previously been applied to another project in the same group, the user must have the group admin role.

    + Attributes (Tag)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + tags (array) - Tags now applied to the project
            + (Tag)

## Remove project tag [/org/{orgId}/project/{projectId}/tags/remove]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to remove a tag from

### Remove a tag from a project [POST]
+ Request (application/json)

    + Required permissions
        + Group Admin

    + Headers

            Authorization: token API_KEY - The user must have an admin role on either the organization or the group which the project belongs too.

    + Attributes (Tag)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + tags (array) - Tags now applied to the project
            + (Tag)

## Project Attributes [/org/{orgId}/project/{projectId}/attributes]
Attributes are static and non-configurable fields which allow to add additional metadata to a project.
Attributes have a pre-defined list of values that a user can select from.

| Business criticality | Environment | Lifecycle stage |
|:--------------------:|:-----------:|:---------------:|
|       critical       |   frontend  |    production   |
|         high         |   backend   |   development   |
|        medium        |   internal  |     sandbox     |
|          low         |   external  |                 |
|                      |    mobile   |                 |
|                      |     saas    |                 |
|                      |    onprem   |                 |
|                      |    hosted   |                 |
|                      | distributed |                 |

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + projectId: `6d5813be-7e6d-4ab8-80c2-1e3e2a454545` (string, required) - The project ID to remove a tag from

### Applying attributes [POST]
Applies an attribute to the provided project.
It is possible to assign multiple values to each attribute, but you can only assign values to one of the predefined attribute categories, using the predefined options for this category.
Assigning an attribute requires the caller to be either an Organization Administrator or a Group Administrator.
Assigning an attribute will override any existing values that the specific attribute already has set.
In order to clear out an attribute value, an empty array can be set.

> **Note:** Organization admins can add an attribute to a Project. However, only Group admins can modify Project attributes in cases where attributes match a policy, because policies can only be managed by Group admins.

+ Request (application/json)

    + Required permissions
        + `View Organization`
        + `View Project`
        + `Edit Project Attributes`

    + Headers

            Authorization: token API_KEY - The user must have an admin role on either the organization or the group which the project belongs too.

    + Attributes (Project attributes)

+ Response 200 (application/json; charset=utf-8)
    + Attributes (object)
        + attributes (Project attributes) - Attributes now applied to the project

# Data Structures

## Project (object)
+ name: snyk/goof (string)
+ id: `af137b96-6966-46c1-826b-2e79ac49bbd9` (string) - The project identifier
+ created: `2018-10-29T09:50:54.014Z` (string) - The date that the project was created on
+ origin: github (string) - The origin the project was added from
+ type: maven (string) - The package manager of the project
+ readOnly: false (boolean) - Whether the project is read-only
+ testFrequency: daily (string) - The frequency of automated Snyk re-test. Can be 'daily', 'weekly or 'never'
+ totalDependencies: 42 (number) - Number of dependencies of the project
+ issueCountsBySeverity (object) - Number of known vulnerabilities in the project, not including ignored issues
    + low: 13 (number) - Number of low severity vulnerabilities
    + medium: 8 (number) - Number of medium severity vulnerabilities
    + high: 1 (number) - Number of high severity vulnerabilities
    + critical: 3 (number) - Number of critical severity vulnerabilities
+ imageId: `sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019` (string) - For docker projects shows the ID of the image
+ imageTag: latest (string) - For docker projects shows the tag of the image
+ imageBaseImage: alpine:3 (string, optional) - For docker projects shows the base image
+ imagePlatform: linux/arm64 (string, optional) - For docker projects shows the platform of the image
+ imageCluster: Production (string, optional) - For Kubernetes projects shows the origin cluster name
+ hostname (string, nullable) - The hostname for a CLI project, null if not set
+ remoteRepoUrl: `https://github.com/snyk/goof.git` (string, optional) - The project remote repository url. Only set for projects imported via the Snyk CLI tool.
+ lastTestedDate: `2019-02-05T08:54:07.704Z` (string) - The date on which the most recent test was conducted for this project
+ owner (object, optional, nullable) - The user who owns the project, null if not set
    {
        "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
        "name": "example-user@snyk.io",
        "username": "exampleUser",
        "email": "example-user@snyk.io"
    }
+ browseUrl: `https://app.snyk.io/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/af137b96-6966-46c1-826b-2e79ac49bbd9` (string) - URL with project overview
+ importingUser (object) - The user who imported the project
    + id: `e713cf94-bb02-4ea0-89d9-613cce0caed2` (string) - The ID of the user.
    + name: `example-user@snyk.io` (string) - The name of the user.
    + username: `exampleUser` (string) - The username of the user.
    + email: `example-user@snyk.io` (string) - The email of the user.
+ isMonitored (boolean) - Describes if a project is currently monitored or it is de-activated
+ branch (string, nullable) - The monitored branch (if available)
+ targetReference (string, nullable) - The identifier for which revision of the resource is scanned by Snyk. For example this may be a branch for SCM project, or a tag for a container image
+ tags (array) - List of applied tags
    + (Tag)
+ attributes (Project attributes) - Applied project attributes
+ remediation (object) - Remediation data (if available)
    + upgrade (object) - Recommended upgrades to apply to the project
        (object)
            + upgradeTo (string, required) - `package@version` to upgrade to
            + upgrades (array[string], required) -  List of `package@version` that will be upgraded as part of this upgrade
            + vulns (array[string], required) - List of vulnerability ids that will be fixed as part of this upgrade
    + patch (object) - Recommended patches to apply to the project
        (object)
           paths (array) - List of paths to the vulnerable dependency that can be patched
    + pin (object) - Recommended pins to apply to the project (Python only)
        (object)
            + upgradeTo (string, required) - `package@version` to upgrade to
            + vulns (array[string], required) - List of vulnerability ids that will be fixed as part of this upgrade
            + isTransitive (boolean) - Describes if the dependency to be pinned is a transitive dependency

## Project without remediation (object)
+ name: snyk/goof (string)
+ id: `af137b96-6966-46c1-826b-2e79ac49bbd9` (string) - The project identifier
+ created: `2018-10-29T09:50:54.014Z` (string) - The date that the project was created on
+ origin: github (string) - The origin the project was added from
+ type: maven (string) - The package manager of the project
+ readOnly: false (boolean) - Whether the project is read-only
+ testFrequency: daily (string) - The frequency of automated Snyk re-test. Can be 'daily', 'weekly or 'never'
+ totalDependencies: 42 (number) - Number of dependencies of the project
+ issueCountsBySeverity (object) - Number of known vulnerabilities in the project, not including ignored issues
    + low: 13 (number) - Number of low severity vulnerabilities
    + medium: 8 (number) - Number of medium severity vulnerabilities
    + high: 1 (number) - Number of high severity vulnerabilities
    + critical: 3 (number) - Number of critical severity vulnerabilities
+ imageId: `sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019` (string) - For docker projects shows the ID of the image
+ imageTag: latest (string) - For docker projects shows the tag of the image
+ imageBaseImage: alpine:3 (string, optional) - For docker projects shows the base image
+ imagePlatform: linux/arm64 (string, optional) - For docker projects shows the platform of the image
+ imageCluster: Production (string, optional) - For Kubernetes projects shows the origin cluster name
+ remoteRepoUrl: `https://github.com/snyk/goof.git` (string, optional) - The project remote repository url. Only set for projects imported via the Snyk CLI tool.
+ lastTestedDate: `2019-02-05T08:54:07.704Z` (string) - The date on which the most recent test was conducted for this project
+ owner (object, optional, nullable) - The user who owns the project, null if not set
    {
        "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
        "name": "example-user@snyk.io",
        "username": "exampleUser",
        "email": "example-user@snyk.io"
    }
+ browseUrl: `https://app.snyk.io/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/af137b96-6966-46c1-826b-2e79ac49bbd9` (string) - URL with project overview
+ importingUser (object) - The user who imported the project
    + id: `e713cf94-bb02-4ea0-89d9-613cce0caed2` (string) - The ID of the user.
    + name: `example-user@snyk.io` (string) - The name of the user.
    + username: `exampleUser` (string) - The username of the user.
    + email: `example-user@snyk.io` (string) - The email of the user.
+ isMonitored (boolean) - Describes if a project is currently monitored or it is de-activated
+ branch (string, nullable) - The monitored branch (if available)
+ targetReference (string, nullable) - The identifier for which revision of the resource is scanned by Snyk. For example this may be a branch for SCM project, or a tag for a container image
+ tags (array) - List of applied tags
    + (Tag)
+ attributes (Project attributes) - Applied project attributes

## Projects filters (object)
+ filters (object)
    + name: snyk/goof (optional, string) - If supplied, only projects that have a name that **starts with** this value will be returned
    + origin: github (optional, string) - If supplied, only projects that exactly match this origin will be returned
    + type: maven (optional, string) - If supplied, only projects that exactly match this type will be returned
    + isMonitored (optional, boolean) - If set to `true`, only include projects which are monitored, if set to `false`, only include projects which are not monitored
    + tags (object)
        + includes (array) - A project must have all provided tags in order to be included in the response. A maximum of 3 tags can be supplied.
            + (Tag)
    + attributes (Project attributes) - When you filter by multiple values on a single attribute, you will return projects that have been assigned one or more of the values in the filter.
    When you filter by multiple attributes, you will return projects which have been assigned values of both attributes in the filter.


## List all projects (object)
+ org (object)
    + name (string)
    + id (string) - The identifier of the org
+ projects (array, fixed-type) - A list of org's projects
    + (Project without remediation)

## Aggregated project issues (object)
+ issues (array, fixed-type) - An array of identified issues
    + (object)
        + id: `npm:ms:20170412` (string, required) - The identifier of the issue
        + issueType: `vuln` (string, required) - type of the issue ('vuln', 'license' or 'configuration')
        + pkgName: `ms` (string, required) - The package name (Non-IaC projects only)
        + pkgVersions: `1.0.0` (array[string], fixed-type, required) - List of affected package versions (Non-IaC projects only)
        + issueData (object, fixed-type, required) - The details of the issue
            + id: `npm:ms:20170412` (string, required) - The identifier of the issue
            + title: `Regular Expression Denial of Service (ReDoS)` (string, required) - The issue title
            + severity: `low` (string, required) - The severity status of the issue, after policies are applied
            + originalSeverity: `high` (string, required) - The original severity status of the issue, as retrieved from Snyk Vulnerability database, before policies are applied
            + url: `https://snyk.io/vuln/npm:ms:20170412` (string, required) - URL to a page containing information about the issue
            + description: `## Overview\r\n[`ms`](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\r\n\r\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS) due to an incomplete fix for previously reported vulnerability [npm:ms:20151024](https://snyk.io/vuln/npm:ms:20151024). The fix limited the length of accepted input string to 10,000 characters, and turned to be insufficient making it possible to block the event loop for 0.3 seconds (on a typical laptop) with a specially crafted string passed to `ms()` function.\r\n\r\n*Proof of concept*\r\n```js\r\nms = require('ms');\r\nms('1'.repeat(9998) + 'Q') // Takes about ~0.3s\r\n```\r\n\r\n**Note:** Snyk's patch for this vulnerability limits input length to 100 characters. This new limit was deemed to be a breaking change by the author.\r\nBased on user feedback, we believe the risk of breakage is _very_ low, while the value to your security is much greater, and therefore opted to still capture this change in a patch for earlier versions as well.  Whenever patching security issues, we always suggest to run tests on your code to validate that nothing has been broken.\r\n\r\nFor more information on `Regular Expression Denial of Service (ReDoS)` attacks, go to our [blog](https://snyk.io/blog/redos-and-catastrophic-backtracking/).\r\n\r\n## Disclosure Timeline\r\n- Feb 9th, 2017 - Reported the issue to package owner.\r\n- Feb 11th, 2017 - Issue acknowledged by package owner.\r\n- April 12th, 2017 - Fix PR opened by Snyk Security Team.\r\n- May 15th, 2017 - Vulnerability published.\r\n- May 16th, 2017 - Issue fixed and version `2.0.0` released.\r\n- May 21th, 2017 - Patches released for versions `>=0.7.1, <=1.0.0`.\r\n\r\n## Details\r\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n\r\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n\r\nLet’s take the following regular expression as an example:\r\n```js\r\nregex = /A(B|C+)+D/\r\n```\r\n\r\nThis regular expression accomplishes the following:\r\n- `A` The string must start with the letter 'A'\r\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n- `D` Finally, we ensure this section of the string ends with a 'D'\r\n\r\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n\r\nIt most cases, it doesn't take very long for a regex engine to find a match:\r\n\r\n```bash\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD\")'\r\n0.04s user 0.01s system 95% cpu 0.052 total\r\n\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX\")'\r\n1.79s user 0.02s system 99% cpu 1.812 total\r\n```\r\n\r\nThe entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n\r\nMost Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n\r\nLet's look at how our expression runs into this problem, using a shorter string: \"ACCCX\". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n1. CCC\r\n2. CC+C\r\n3. C+CC\r\n4. C+C+C.\r\n\r\nThe engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n\r\nFrom there, the number of steps the engine must use to validate a string just continues to grow.\r\n\r\n| String | Number of C's | Number of steps |\r\n| -------|-------------:| -----:|\r\n| ACCCX | 3 | 38\r\n| ACCCCX | 4 | 71\r\n| ACCCCCX | 5 | 136\r\n| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n\r\n\r\nBy the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\r\n\r\n\r\n## Remediation\r\nUpgrade `ms` to version 2.0.0 or higher.\r\n\r\n## References\r\n- [GitHub PR](https://github.com/zeit/ms/pull/89)\r\n- [GitHub Commit](https://github.com/zeit/ms/pull/89/commits/305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef)` (string) - The issue description
            + identifiers (object) - External identifiers assigned to the issue (Non-IaC projects only)
                + CVE (array[string]) - Common Vulnerability Enumeration identifiers
                + CWE: `CWE-400` (array[string]) - Common Weakness Enumeration identifiers
                + OSVDB (array[string]) - Identifiers assigned by the Open Source Vulnerability Database (OSVDB)
            + credit: `Snyk Security Research Team` (array[string]) - The list of people responsible for first uncovering or reporting the issue (Non-IaC projects only)
            + exploitMaturity: `no-known-exploit` (string, required) - The exploit maturity of the issue
            + semver (object) - The ranges that are vulnerable and unaffected by the issue (Non-IaC projects only)
                + vulnerable: `>=0.7.1 <2.0.0` (array[string]) - The ranges that are vulnerable to the issue. May be an array or a string.
                + unaffected (string) - The ranges that are unaffected by the issue
            + publicationTime: `2017-05-15T06:02:45Z` (string) - The date that the vulnerability was first published by Snyk (Non-IaC projects only)
            + disclosureTime: `2017-04-11T21:00:00Z` (string) - The date that the vulnerability was first disclosed
            + CVSSv3: `CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L` (string) - The CVSS v3 string that signifies how the CVSS score was calculated (Non-IaC projects only)
            + cvssScore: `3.7` (number) - The CVSS score that results from running the CVSSv3 string (Non-IaC projects only)
            + language: `js` (string) - The language of the issue (Non-IaC projects only)
            + patches (array) - A list of patches available for the given issue (Non-IaC projects only)
                + (object)
                    + id: `patch:npm:ms:20170412:0` (string) - The identifier of the patch
                    + urls: `https://snyk-patches.s3.amazonaws.com/npm/ms/20170412/ms_100.patch` (array[string]) - The URLs where the patch files can be downloaded
                    + version: `=1.0.0` (string) - The version number(s) that the patch can be applied to
                    + comments (array[string]) - Any comments about the patch
                    + modificationTime: `2019-12-03T11:40:45.863964Z` (string) - When the patch was last modified
            + nearestFixedInVersion: `2.0.0` (string) - Nearest version which includes a fix for the issue. This is populated for container projects only. (Non-IaC projects only)
            + path: `[DocId: 1].input.spec.template.spec.containers[snyk2].securityContext.privileged` (string, required) - Path to the resource property violating the policy within the scanned project. (IaC projects only)
            + violatedPolicyPublicId: `SNYK-CC-K8S-1` (string, required) - The ID of the violated policy in the issue (IaC projects only)
            + isMaliciousPackage: `true` (boolean) - Whether the issue is intentional, indicating a malicious package
        + introducedThrough (array) - The list of what introduced the issue (it is available only for container project with Dockerfile)
            + (object)
                + kind: `imageLayer` (string, required) - The data kind, each data kind can have different data fields e.g. "ImageLayer"
                + data (object, required) - The information about what introduced the issue. The data structure varies based on the data kind.
        + isPatched (boolean, required) - Whether the issue has been patched (Non-IaC projects only)
        + isIgnored (boolean, required) - Whether the issue has been ignored
        + ignoreReasons (array) - The list of reasons why the issue was ignored
            + (object)
                + reason (string) - A reason why the issue was ignored
                + expires (string) - The date when the ignore will no longer apply
                + source (enum[string]) - The place where the ignore rule was applied from
                    + Members
                        + `cli` - The ignore was applied via the CLI or filesystem
                        + `api` - The ignore was applied via the API or website
        + fixInfo (object) - Information about fix/upgrade/pinnable options for the issue (Non-IaC projects only)
            + isUpgradable (boolean) - Whether all of the issue's paths are upgradable
            + isPinnable (boolean) - Whether the issue can be fixed by pinning a transitive
            + isPatchable (boolean) - Whether all the of issue's paths are patchable
            + isFixable (boolean) - Whether all of the issue's paths are fixable. Paths that are already patched are not considered fixable unless they have an alternative remediation (e.g. pinning or upgrading). An upgrade path where the only changes are in transitive dependencies is only considered fixable if the package manager supports it.
            + isPartiallyFixable (boolean) - Whether any of the issue's paths can be fixed. Paths that are already patched are not considered fixable unless they have an alternative remediation (e.g. pinning or upgrading).  An upgrade path where the only changes are in transitive dependencies is only considered fixable if the package manager supports it.
            + nearestFixedInVersion: `2.0.0` (string) - Nearest version which includes a fix for the issue. This is populated for container projects only.
            + fixedIn: `2.0.0` (array) - The set of versions in which this issue has been fixed. If the issue spanned multiple versions (i.e. `1.x` and `2.x`) then there will be multiple `fixedIn` entries
        + priority (object) - Information about the priority of the issue (Non-IaC projects only)
            + score: `399` (number) - The priority score of the issue
            + factors (array) - The list of factors that contributed to the priority of the issue
                + (object)
                + name: `isFixable` (string) - The name of the factor e.g. "cvssScore"
                + description: `Has a fix available` (string) - Text description of the factor. Snyk may update this without notice to improve the explanation the factor.
        + links (object) - Onward links from this record (Non-IaC projects only)
            + paths (string) - The URL for the dependency paths that introduce this issue

## Aggregated project issues filters
+ includeDescription (boolean, optional) - If set to `true`, Include issue's description, if set to `false` (by default), it won't (Non-IaC projects only)
+ includeIntroducedThrough (boolean, optional) - If set to `true`, Include issue's introducedThrough, if set to `false` (by default), it won't. It's for container only projects (Non-IaC projects only)
+ filters (object, optional)
    + severities (array, optional) - The severity levels of issues to filter the results by
        + critical (string, optional) - Include issues which are critical severity
        + high (string, optional) - Include issues which are high severity
        + medium (string, optional) - Include issues which are medium severity
        + low (string, optional) - Include issues which are low severity
    + exploitMaturity (array, optional) - The exploit maturity levels of issues to filter the results by (Non-IaC projects only)
        + `mature` (string, optional) - Snyk has a published code exploit for this vulnerability
        + `proof-of-concept` (string, optional) - Snyk has a proof-of-concept or detailed explanation of how to exploit this vulnerability
        + `no-known-exploit` (string, optional) - Snyk did not find a proof-of-concept or a published exploit for this vulnerability
        + `no-data` (string, optional) - Currently, there is no data for this distro
    + types (array, optional) - The type of issues to filter the results by (Non-IaC projects only)
        + vuln (string, optional) - Include issues which are vulnerabilities
        + license (string, optional) - Include issues which are licenses
    + ignored (boolean, optional) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean, optional) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched (Non-IaC projects only)
    + priority (object, optional) - The priority to filter the issues by (Non-IaC projects only)
        + score (object, optional) - Include issues where the priority score is between min and max
            + min: 0 (number, optional)
            + max: 1000 (number, optional)

## Issue paths (object)
+ snapshotId (string) - The identifier of the snapshot for which the paths have been found
+ paths (array, fixed-type) - A list of the dependency paths that introduce the issue
    + (array, fixed-type) - A list of the packages in the path
        + (object) - A package in the path
            + name (string) - The package name
            + version (string) - The package version
            + fixVersion (string, optional) - The version to upgrade the package to in order to resolve the issue. This will only appear on the first element of the path, and only if the issue can be fixed by upgrading packages. Note that if the fix requires upgrading transitive dependencies, `fixVersion` will be the same as `version`.
+ total (number) - The total number of results
+ links (object) - Onward links from this record
    + prev (optional, string) - The URL of the previous page of paths for the issue, if not on the first page
    + next (optional, string) - The URL of the next page of paths for the issue, if not on the last page
    + last (string) - The URL of the last page of paths for the issue

## Project snapshots (object)
+ snapshots (array, fixed-type) - A list of the project's snapshots, ordered according to date (latest first).
    + (object)
        + id (string, required) - The snapshot identifier
        + created: `2018-10-29T09:50:54.014Z` (string, required) - The date that the snapshot was taken
        + totalDependencies (number, required) - Number of dependencies of the project
        + issueCounts (object, required) - Number of known vulnerabilities in the project, not including ignored issues
            + vuln (object, optional)
                + low (number, required) - Number of low severity vulnerabilities
                + medium (number, required) - Number of medium severity vulnerabilities
                + high (number, required) - Number of high severity vulnerabilities
                + critical (number, required) - Number of critical severity vulnerabilities
            + license (object, optional)
                + low (number, required) - Number of low severity vulnerabilities
                + medium (number, required) - Number of medium severity vulnerabilities
                + high (number, required) - Number of high severity vulnerabilities
                + critical (number, required) - Number of critical severity vulnerabilities
            + sast (object, optional)
                + low (number, required) - Number of low severity vulnerabilities
                + medium (number, required) - Number of medium severity vulnerabilities
                + high (number, required) - Number of high severity vulnerabilities
                + critical (number, required) - Number of critical severity vulnerabilities
        + imageId: `sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019` (string, optional): For container projects shows the ID of the image
        + imageTag: `latest` (string, optional): For container projects shows the tag of the image
        + imageBaseImage: `alpine:3` (string, optional): For container projects shows the base image
        + imagePlatform: `linux/arm64` (string, optional): For container projects shows the platform of the image
        + method (enum) - The method by which this snapshot was created.
            + Members
                + `api`
                + `cli`
                + `recurring`
                + `web`
                + `web-test`
                + `wizard`
+ total (number) - The total number of results

## Project snapshots filters
+ filters (object)
    + imageId: `sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019` (string) - For container projects, filter by the ID of the image

## Project dependency graph (object)
+ depGraph (object, required) - The dependency-graph object
    + schemaVersion (string, required) - The scheme version of the depGraph object
    + pkgManager (object, required) - The package manager of the project
        + name (string, required) - The name of the package manager
        + version (string) - The version of the package manager
        + repositories (array, fixed-type)
            + (object, required)
               + alias (string, required)
    + pkgs (array, fixed-type, required) - A list of dependencies in the project
        + (object, required)
            + id (string, required) - The internal id of the package
            + info (object, required)
                + name (string, required) - The name of the package
                + version (string) - The version of the package
    + graph (object, required) - A directional graph of the packages in the project
        + rootNodeId (string, required) - The internal id of the root node
        + nodes (array, fixed-type) - A list of the first-level packages
            + (object, required)
                + nodeId (string, required) - The internal id of the node
                + pkgId (string, required) - The id of the package
                + deps (array, fixed-type, required) - A list of the direct dependencies of the package
                    + (object, required)
                        + nodeId (string, required) - The id of the node

## Project issues filters
+ filters (object)
    + severities (array) - The severity levels of issues to filter the results by
        + critical (string) - Include issues which are critical severity
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + exploitMaturity (array) - The exploit maturity levels of issues to filter the results by
        + `mature` (string) - Snyk has a published code exploit for this vulnerability
        + `proof-of-concept` (string) - Snyk has a proof-of-concept or detailed explanation of how to exploit this vulnerability
        + `no-known-exploit` (string) - Snyk did not find a proof-of-concept or a published exploit for this vulnerability
        + `no-data` (string) - Currently, there is no data for this distro
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched
    + priorityScore (object) - Include issues that have a priority score between `min` and `max`
        + min: 0 (optional, number)
        + max: 1000(optional, number)

## All ignores (object)
+ *issueId (string)* (array[Ignore], required) - The issue ID that should be ignored.

## Ignore (object)
+ *ignorePath (string)* (object, required) - The path that should be ignored. Wildcards can be specified with a `*`.
    + reason (string) - The reason that the issue was ignored.
    + reasonType (enum[string]) - The classification of the ignore.
        + Members
            + `not-vulnerable` - The app is not vulnerable.
            + `wont-fix` - The app may be vulnerable, but you accept the risk.
            + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
    + ignoredBy (object) - The person who ignored the issue.
        + name (string, required) - The name of the person who ignored the issue.
        + email (string, required) - The email of the person who ignored the issue.
        + id (string) - The user ID of the person who ignored the issue.
    + disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
    + expires (string) - The timestamp that the issue will no longer be ignored.
    + created (string) - The timestamp that the issue was ignored.

## Ignores (array)
+ (object)
    + *ignorePath (string)* (object, required) - The path that should be ignored. Wildcards can be specified with a `*`.
        + reason (string) - The reason that the issue was ignored.
        + reasonType (enum[string]) - The classification of the ignore.
            + Members
                + `not-vulnerable` - The app is not vulnerable.
                + `wont-fix` - The app may be vulnerable, but you accept the risk.
                + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
        + ignoredBy (object) - The person who ignored the issue.
            + name (string, required) - The name of the person who ignored the issue.
            + email (string, required) - The email of the person who ignored the issue.
            + id (string) - The user ID of the person who ignored the issue.
        + disregardIfFixable (boolean) - Only ignore the issue if no upgrade or patch is available.
        + expires (string) - The timestamp that the issue will no longer be ignored.
        + created (string) - The timestamp that the issue was ignored.

## Ignore rule (object)
+ ignorePath (string) - The path to ignore (default is `*` which represents all paths).
+ reason (string) - The reason that the issue was ignored.
+ reasonType (enum[string], required) - The classification of the ignore.
    + Members
        + `not-vulnerable` - The app is not vulnerable.
        + `wont-fix` - The app may be vulnerable, but you accept the risk.
        + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
+ disregardIfFixable (boolean, required) - Only ignore the issue if no upgrade or patch is available.
+ expires (string) - The timestamp that the issue will no longer be ignored.

## Ignore rules (array)
+ (object)
    + ignorePath (string) - The path to ignore (default is `*` which represents all paths).
    + reason (string) - The reason that the issue was ignored.
    + reasonType (enum[string]) - The classification of the ignore.
        + Members
            + `not-vulnerable` - The app is not vulnerable.
            + `wont-fix` - The app may be vulnerable, but you accept the risk.
            + `temporary-ignore` - You don't want to fix the issue at the moment for any reason.
    + disregardIfFixable (boolean, required) - Only ignore the issue if no upgrade or patch is available.
    + expires (string) - The timestamp that the issue will no longer be ignored.

## All jira issues (object)
+ *issueId (string)* (array[Jira issue], required) - The issue ID and relating jira issue.

## Jira issue (object)
+ jiraIssue (object) - The details about the jira issue.
    + id (string) - The id of the issue in Jira.
    + key (string) - The key of the issue in Jira.

## Jira issue request (object)
+ fields (object)
    + project (object) - See https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post for details of what to send as fields.
    + issuetype (object) - See https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post for details of what to send as fields.
    + summary (string) - See https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post for details of what to send as fields.

## Project settings (object)
+ autoDepUpgradeEnabled (boolean, optional) - If set to `true`, Snyk will raise dependency upgrade PRs automatically.
+ autoDepUpgradeIgnoredDependencies (array[string], optional) - An array of comma-separated strings with names of dependencies you wish Snyk to ignore to upgrade.
+ autoDepUpgradeMinAge (number, optional) - The age (in days) that an automatic dependency check is valid for
+ autoDepUpgradeLimit (number, optional)  - The limit on auto dependency upgrade PRs.
+ pullRequestFailOnAnyVulns (boolean, optional) - If set to `true`, fail Snyk Test if the repo has any vulnerabilities. Otherwise, fail only when the PR is adding a vulnerable dependency.
+ pullRequestFailOnlyForHighSeverity (boolean, optional) - If set to `true`, fail Snyk Test only for high and critical severity vulnerabilities
+ pullRequestTestEnabled (boolean, optional) - If set to `true`, Snyk Test checks PRs for vulnerabilities.:cq
+ pullRequestAssignment (PullRequestAssignment, optional) - assign Snyk pull requests
+ autoRemediationPrs (AutoRemediationPrs, optional) - Defines automatic remediation policies

## Project move (object)
+ targetOrgId (string) - The ID of the organization that the project should be moved to. The API_KEY must have group admin permissions. If the project is moved to a new group, a personal level API key is needed.
# Group Dependencies
Dependencies are packages/modules that your projects depend on.

Current rate limit is up to 150 requests per minute, per user.
For more information about rate-limiting see: [https://snyk.docs.apiary.io/#introduction/rate-limiting](https://snyk.docs.apiary.io/#introduction/rate-limiting)

## Dependencies by organization [/org/{orgId}/dependencies{?sortBy,order,page,perPage}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list projects for. The `API_KEY` must have access to this organization.
    + sortBy: `dependency` (enum[string], optional) - The field to sort results by.
        + Default: `dependency`
        + Members
            + `projects`
            + `dependency`
            + `severity`
            + `dependenciesWithIssues`
    + order (enum[string], optional) - The direction to sort results by.
        + Default: `asc`
        + Members
            + `asc`
            + `desc`
    + page (number, optional) - The page of results to fetch.
        + Default: `1`
    + perPage (number, optional) - The number of results to fetch per page (maximum is 1000).
        + Default: `20`


### List all dependencies [POST]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`
    + Headers

            Authorization: token API_KEY

    + Attributes (Dependencies filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Dependencies)

    + Headers

            Link: <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbed/dependencies?order=asc&page=1&perPage=20&sortBy=dependency>; rel=last

    + Body

            {
                "results": [
                    {
                        "id": "gulp@3.9.1",
                        "name": "gulp",
                        "version": "3.9.1",
                        "latestVersion": "4.0.0",
                        "latestVersionPublishedDate": "2018-01-01T01:29:06.863Z",
                        "firstPublishedDate": "2013-07-04T23:27:07.828Z",
                        "isDeprecated": false,
                        "deprecatedVersions": ["0.0.1", "0.0.2", "0.0.3"],
                        "licenses": [
                            {
                                "id": "snyk:lic:npm:gulp:MIT",
                                "title": "MIT license",
                                "license": "MIT"
                            }
                        ],
                        "dependenciesWithIssues": [
                            "minimatch@2.0.10",
                            "minimatch@0.2.14"
                        ],
                        "type": "npm",
                        "projects": [
                            {
                                "name": "atokeneduser/goof",
                                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
                            }
                        ],
                        "copyright": [
                            "Copyright (c) 2013-2018 Blaine Bublitz <blaine.bublitz@gmail.com>",
                            "Copyright (c) Eric Schoffstall <yo@contra.io> and other contributors"
                        ]
                    }
                ],
                "total": 1
            }

# Data Structures

## Dependencies (object)
+ results (array, fixed-type, required) - A list of issues
    + (object, required)
        + id (string, required) - The identifier of the package
        + name (string, required) - The name of the package
        + version (string, required) - The version of the package
        + latestVersion (string) - The latest version available for the specified package
        + latestVersionPublishedDate (string) - The timestamp for when the latest version of the specified package was published.
        + firstPublishedDate (string) - The timestamp for when the specified package was first published.
        + isDeprecated (boolean) - True if the latest version of the package is marked as deprecated; False otherwise.
        + deprecatedVersions (array[string]) - The numbers for those versions that are marked as deprecated
        + dependenciesWithIssues (array[string]) - The identifiers of dependencies with issues that are depended upon as a result of this dependency
        + type (string, required) - The package type of the dependency
        + issuesCritical (number) - The number of critical severity issues in this dependency
        + issuesHigh (number) - The number of high severity issues in this dependency
        + issuesMedium (number) - The number of medium severity issues in this dependency
        + issuesLow (number) - The number of low severity issues in this dependency
        + licenses (array, fixed-type, required) - The licenses of the dependency
            + (object)
                + id (string, required) - The identifier of the license
                + title (string, required) - The title of the license
                + license (string, required) - The type of the license
        + projects (array, fixed-type, required) - The projects which depend on the dependency
            + (object)
                + id (string, required) - The identifier of the project
                + name (string, required) - The name of the project
        + copyright (array[string]) - The copyright notices for the package
+ total (number) - The number of results returned

## Dependencies filters
+ filters (object)
    + languages (array) - The type of languages to filter the results by
        + cpp (string) - Include issues which are for C++ projects (cpp)
        + dockerfile (string) - Include issues which are for Docker projects (apk, deb or rpm package managers)
        + dotnet (string) - Include issues which are for .Net projects (nuget)
        + elixir (string) - Include issues which are for Elixir projects (hex)
        + golang (string) - Include issues which are for Go projects (golangdep, govendor or gomodules package managers)
        + helm (string) - Include issues which are for Helm projects (helmconfig)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + javascript (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + kubernetes (string) - Include issues which are for Kubernetes projects (k8sconfig)
        + linux (string) - Include issues which are for Linux projects (apk, deb or rpm package managers)
        + php (string) - Include issues which are for PHP projects (composer)
        + python (string) - Include issues which are for Python projects (pip or poetry package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + swift-objective-c (string) - Include issues which are for Swift / Objective C projects (cocoapods)
        + terraform (string) - Include issues which are for Terraform projects (terraformconfig)
    + projects (array) - The list of project IDs to filter the results by
    + dependencies (array) - The list of dependency IDs to filter the results by (i.e amdefine@1.0.1 or org.javassist:javassist@3.18.1-GA)
    + licenses (array) - The list of license IDs to filter the results by
    + severity (array) - The severities to filter the results by
        + critical (string) - Include dependencies with at least one critical severity issue assigned
        + high (string) - Include dependencies with at least one high severity issue assigned
        + medium (string) - Include dependencies with at least one medium severity issue assigned
        + low (string) - Include dependencies with at least one low severity issue assigned
    + depStatus (string) - Status of the dependency. Requires reporting entitlement. Options: `deprecated` - Include only deprecated packages; `notDeprecated` - Include all packages that are not marked as deprecated; `any` - Include all packages (default)
# Group Licenses
The licenses which the packages/modules in your projects use.

> **Note:** When you import or update projects, changes will be reflected on the endpoint results after a ten-second delay.

## Licenses by organization [/org/{orgId}/licenses{?sortBy,order}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list projects for. The `API_KEY` must have access to this organization.
    + sortBy: `license` (enum[string], optional) - The field to sort results by.
        + Default: `license`
        + Members
            + `license`
            + `dependencies`
            + `projects`
            + `severity`
    + order (enum[string], optional) - The direction to sort results by.
        + Default: `asc`
        + Members
            + `asc`
            + `desc`

### List all licenses [POST]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`

    + Headers

            Authorization: token API_KEY

    + Attributes (Licenses filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Licenses)

    + Body

            {
                "results": [
                    {
                        "id": "MIT",
                        "severity": "none",
                        "instructions": "",
                        "dependencies": [
                            {
                                "id": "accepts@1.0.0",
                                "name": "accepts",
                                "version": "1.0.0",
                                "packageManager": "npm"
                            }
                        ],
                        "projects": [
                            {
                                "name": "atokeneduser/goof",
                                "id": "6d5813be-7e6d-4ab8-80c2-1e3e2a454545"
                            }
                        ]
                    }
                ],
                "total": 1
            }

# Data Structures

## Licenses (object)
+ results (array, fixed-type, required) - A list of licenses
    + (object, required)
        + id (string, required) - The identifier of the license
        + severity (enum[string]) - The severity assigned to this license
            + Members
                + none (string) - No severity defined
                + high (string) - High severity
                + medium (string) - Medium severity
                + low (string) - Low severity
            + Sample: none
        + instructions (string) - Custom instructions assigned to this license
        + dependencies (array, fixed-type, required) - The dependencies of projects in the organization which have the license
            + (object)
                + id (string, required) - The identifier of the package
                + name (string, required) - The name of the package
                + version (string, required) - The version of the package
                + packageManager (string, required) - The package manager of the dependency
        + projects (array, fixed-type, required) - The projects which contain the license
            + (object)
                + id (string, required) - The identifier of the project
                + name (string, required) - The name of the project
+ total (number) - The number of results returned

## Licenses filters
+ filters (object)
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + cpp (string) - Include issues which are for C++ projects (cpp)
    + projects (array) - The list of project IDs to filter the results by
    + dependencies (array) - The list of dependency IDs to filter the results by
    + licenses (array) - The list of license IDs to filter the results by
    + severity (array) - The severities to filter the results by
        + none (string) - Include licenses with no severity assigned
        + high (string) - Include licenses with high severity assigned
        + medium (string) - Include licenses with medium severity assigned
        + low (string) - Include licenses with low severity assigned
# Group Entitlements
Entitlements are specific abilities an organization has enabled.

## Entitlements by organization [/org/{orgId}/entitlements]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list entitlements for. The `API_KEY` must have access to this organization.

### List all entitlements [GET]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Entitlements`

    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

    + Body

            {
                "licenses": true,
                "reports": true,
                "fullVulnDB": false
            }


## A specific entitlement by organization [/org/{orgId}/entitlement/{entitlementKey}]
It is possible to query an organization for a specific entitlement, getting its value.

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to query the entitlement for. The `API_KEY` must have access to this organization.
    + entitlementKey: `reports` (enum[string], required) - The entitlement to query.
    
        + Members
          + `licenses`
          + `reports`
          + `fullVulnDB`

### Get an organization's entitlement value [GET]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Entitlements`

    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

    + Body

            true
# Group Test
Test a package for issues with Snyk.

## Maven [/test/maven/{groupId}/{artifactId}/{version}{?org,repository}]
Test for issues in Maven files.

### Test for issues in a public package by group id, artifact id and version  [GET /test/maven/{groupId}/{artifactId}/{version}{?org,repository}]
You can test `maven` packages for issues according to their [coordinates](https://maven.apache.org/pom.html#Maven_Coordinates): group ID, artifact ID and version. The repository hosting the package may also be customized (see the `repository` query parameter).

+ Parameters
    + groupId: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + artifactId: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The Maven repository hosting this package. The default value is Maven Central. More than one value is supported, in order.


+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "title": "Arbitrary Code Execution",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.flex.blazeds:blazeds](https://github.com/apache/flex-blazeds) is an application development framework for easily building Flash-based applications for mobile devices, web browsers, and desktops.\n\n\nAffected versions of this package are vulnerable to Arbitrary Code Execution.\nThe AMF deserialization implementation of Flex BlazeDS is vulnerable to Deserialization of Untrusted Data. By sending a specially crafted AMF message, it is possible to make the server establish a connection to an endpoint specified in the message and request an RMI remote object from that endpoint. This can result in the execution of arbitrary code on the server via Java deserialization.\r\n\r\nStarting with BlazeDS version `4.7.3`, Deserialization of XML is disabled completely per default, while the `ClassDeserializationValidator` allows deserialization of whitelisted classes only. BlazeDS internally comes with the following whitelist:\r\n```\r\nflex.messaging.io.amf.ASObject\r\nflex.messaging.io.amf.SerializedObject\r\nflex.messaging.io.ArrayCollection\r\nflex.messaging.io.ArrayList\r\nflex.messaging.messages.AcknowledgeMessage\r\nflex.messaging.messages.AcknowledgeMessageExt\r\nflex.messaging.messages.AsyncMessage\r\nflex.messaging.messages.AsyncMessageExt\r\nflex.messaging.messages.CommandMessage\r\nflex.messaging.messages.CommandMessageExt\r\nflex.messaging.messages.ErrorMessage\r\nflex.messaging.messages.HTTPMessage\r\nflex.messaging.messages.RemotingMessage\r\nflex.messaging.messages.SOAPMessage\r\njava.lang.Boolean\r\njava.lang.Byte\r\njava.lang.Character\r\njava.lang.Double\r\njava.lang.Float\r\njava.lang.Integer\r\njava.lang.Long\r\njava.lang.Object\r\njava.lang.Short\r\njava.lang.String\r\njava.util.ArrayList\r\njava.util.Date\r\njava.util.HashMap\r\norg.w3c.dom.Document\r\n```\n\n## Remediation\n\nUpgrade `org.apache.flex.blazeds:blazeds` to version 4.7.3 or higher.\n\n\n## References\n\n- [CVE-2017-3066](https://nvd.nist.gov/vuln/detail/CVE-2017-5641)\n\n- [Github Commit](https://github.com/apache/flex-blazeds/commit/f861f0993c35e664906609cad275e45a71e2aaf1)\n\n- [Github Release Notes](https://github.com/apache/flex-blazeds/blob/master/RELEASE_NOTES)\n\n- [Securitytracker Issue](http://www.securitytracker.com/id/1038364)\n",
                  "functions": [],
                  "from": [
                    "org.apache.flex.blazeds:blazeds@4.7.2"
                  ],
                  "package": "org.apache.flex.blazeds:blazeds",
                  "version": "4.7.2",
                  "severity": "critical",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[,4.7.3)"
                    ]
                  },
                  "publicationTime": "2017-08-09T14:17:08Z",
                  "disclosureTime": "2017-04-25T21:00:00Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2017-5641"
                    ],
                    "CWE": [
                      "CWE-502"
                    ]
                  },
                  "credit": [
                    "Markus Wulftange"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvssScore": 9.8,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.flex.blazeds:blazeds@4.7.3"
                  ]
                }
              ],
              "licenses": []
            },
            "dependencyCount": 1,
            "org": {
              "name": "atokeneduser",
              "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
            },
            "licensesPolicy": null,
            "packageManager": "maven"
        }



### Test maven file [POST /test/maven{?org,repository}]
You can test your Maven packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `pom.xml`.

Additional manifest files, if they are needed, like parent `pom.xml` files, child poms, etc., according the the definitions in the target `pom.xml` file, should be supplied in the `additional` body parameter.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The Maven repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (Maven request payload)


+ Response 200 (application/json; charset=utf-8)


        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-JAVA-AXIS-30071",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30071",
                  "title": "Man-in-the-Middle (MitM)",
                  "type": "vuln",
                  "description": "## Overview\n\n[axis:axis](https://search.maven.org/search?q=g:axis) is an implementation of the SOAP (\"Simple Object Access Protocol\") submission to W3C.\n\n\nAffected versions of this package are vulnerable to Man-in-the-Middle (MitM).\nIt does not verify the requesting server's hostname against existing domain names in the SSL Certificate. \r\n\r\n## Details\r\nThe `getCN` function in Apache Axis 1.4 and earlier does not properly verify that the server hostname matches a domain name in the subject's `Common Name (CN)` or `subjectAltName` field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via a certificate with a subject that specifies a common name in a field that is not the CN field.  \r\n\r\n**NOTE:** this issue exists because of an incomplete fix for [CVE-2012-5784](https://snyk.io/vuln/SNYK-JAVA-AXIS-30189).\n\n## Remediation\n\nThere is no fixed version for `axis:axis`.\n\n\n## References\n\n- [Axis Issue](https://issues.apache.org/jira/browse/AXIS-2905)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3596)\n\n- [Redhat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-3596)\n",
                  "functions": [],
                  "from": [
                    "axis:axis@1.4"
                  ],
                  "package": "axis:axis",
                  "version": "1.4",
                  "severity": "medium",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[0,]"
                    ]
                  },
                  "publicationTime": "2014-08-18T16:51:53Z",
                  "disclosureTime": "2014-08-18T16:51:53Z",
                  "isUpgradable": false,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2014-3596"
                    ],
                    "CWE": [
                      "CWE-297"
                    ]
                  },
                  "credit": [
                    "David Jorm",
                    "Arun Neelicattu"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                  "cvssScore": 5.4,
                  "patches": [],
                  "upgradePath": []
                },
                {
                  "id": "SNYK-JAVA-AXIS-30189",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30189",
                  "title": "Man-in-the-Middle (MitM)",
                  "type": "vuln",
                  "description": "## Overview\n\n[axis:axis](https://search.maven.org/search?q=g:axis) is an implementation of the SOAP (\"Simple Object Access Protocol\") submission to W3C.\n\n\nAffected versions of this package are vulnerable to Man-in-the-Middle (MitM).\nIt does not verify the requesting server's hostname against existing domain names in the SSL Certificate.\r\n\r\n## Details\r\nApache Axis 1.4 and earlier does not properly verify that the server hostname matches a domain name in the subject's `Common Name (CN)` or `subjectAltName` field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.\n\n## Remediation\n\nThere is no fixed version for `axis:axis`.\n\n\n## References\n\n- [Jira Issue](https://issues.apache.org/jira/browse/AXIS-2883)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-5784)\n\n- [Texas University](http://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)\n",
                  "functions": [],
                  "from": [
                    "axis:axis@1.4"
                  ],
                  "package": "axis:axis",
                  "version": "1.4",
                  "severity": "medium",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[0,]"
                    ]
                  },
                  "publicationTime": "2017-03-13T08:00:21Z",
                  "disclosureTime": "2012-11-04T22:55:00Z",
                  "isUpgradable": false,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2012-5784"
                    ],
                    "CWE": [
                      "CWE-20"
                    ]
                  },
                  "credit": [
                    "Alberto Fernández"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                  "cvssScore": 5.4,
                  "patches": [],
                  "upgradePath": []
                },
                {
                  "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-174781",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-174781",
                  "title": "Access Control Bypass",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.zookeeper:zookeeper](http://zookeeper.apache.org/) is a centralized service for maintaining configuration information, naming, providing distributed synchronization, and providing group services.\n\n\nAffected versions of this package are vulnerable to Access Control Bypass.\nZooKeeper’s `getACL()` method doesn’t check any permission when retrieving the ACLs of the requested node and returns all information contained in the ACL `Id` field as plain text string. \r\nIf Digest Authentication is in use, the unsalted hash value will be disclosed by the `getACL()` method for unauthenticated or unprivileged users.\n\n## Remediation\n\nUpgrade `org.apache.zookeeper:zookeeper` to version 3.4.14, 3.5.5 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/apache/zookeeper/commit/af741cb319d4760cfab1cd3b560635adacd8deca)\n\n- [Jira Issue](https://issues.apache.org/jira/browse/ZOOKEEPER-1392)\n\n- [ZooKeeper Security](https://zookeeper.apache.org/security.html#CVE-2019-0201)\n",
                  "functions": [],
                  "from": [
                    "org.apache.zookeeper:zookeeper@3.5"
                  ],
                  "package": "org.apache.zookeeper:zookeeper",
                  "version": "3.5",
                  "severity": "medium",
                  "exploitMaturity": "proof-of-concept",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[,3.4.14)",
                      "[3.5.0-alpha, 3.5.5)"
                    ]
                  },
                  "publicationTime": "2019-05-23T15:00:13Z",
                  "disclosureTime": "2019-05-23T15:00:13Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2019-0201"
                    ],
                    "CWE": [
                      "CWE-288"
                    ]
                  },
                  "credit": [
                    "Harrison Neal"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O",
                  "cvssScore": 4.3,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.zookeeper:zookeeper@3.5.5"
                  ]
                },
                {
                  "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-31035",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-31035",
                  "title": "Insufficiently Protected Credentials",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.zookeeper:zookeeper](http://zookeeper.apache.org/) is a centralized service for maintaining configuration information, naming, providing distributed synchronization, and providing group services.\n\n\nAffected versions of this package are vulnerable to Insufficiently Protected Credentials.\nThe logs cleartext admin passwords, which allows local users to obtain sensitive information by reading the log.\n\n## Remediation\n\nUpgrade `org.apache.zookeeper:zookeeper` to version 3.4.7, 3.5.1-alpha or higher.\n\n\n## References\n\n- [Jira Issue](https://issues.apache.org/jira/browse/ZOOKEEPER-1917)\n\n- [Redhat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=1067265)\n",
                  "functions": [],
                  "from": [
                    "org.apache.zookeeper:zookeeper@3.5"
                  ],
                  "package": "org.apache.zookeeper:zookeeper",
                  "version": "3.5",
                  "severity": "medium",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[3.3.0,3.4.7)",
                      "[3.5.0-alpha,3.5.1-alpha)"
                    ]
                  },
                  "publicationTime": "2016-10-05T08:19:32Z",
                  "disclosureTime": "2014-04-17T14:55:00Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2014-0085"
                    ],
                    "CWE": [
                      "CWE-522"
                    ]
                  },
                  "credit": [
                    "Unknown"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                  "cvssScore": 4,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.zookeeper:zookeeper@3.5.5"
                  ]
                },
                {
                  "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-31428",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-31428",
                  "title": "Denial of Service (DoS)",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.zookeeper:zookeeper](http://zookeeper.apache.org/) is a centralized service for maintaining configuration information, naming, providing distributed synchronization, and providing group services.\n\n\nAffected versions of this package are vulnerable to Denial of Service (DoS).\nFour letter zookeeper commands (such as `wchp`/`wchc` ) are not properly handled, which leads to the server unable to serve legitimate client requests.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\n\nUpgrade `org.apache.zookeeper:zookeeper` to version 3.4.10, 3.5.3-beta or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/apache/zookeeper/pull/179/commits/b4c421d5f42d8af376b1d422e73cc210133d367f)\n\n- [Jira Issue](https://issues.apache.org/jira/browse/ZOOKEEPER-2693)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5637)\n",
                  "functions": [
                    {
                      "functionId": {
                        "className": "org.apache.zookeeper.server.NIOServerCnxn",
                        "functionName": "checkFourLetterWord"
                      },
                      "version": [
                        "[,3.3.7)"
                      ]
                    },
                    {
                      "functionId": {
                        "className": "org.apache.zookeeper.server.NettyServerCnxn",
                        "functionName": "checkFourLetterWord"
                      },
                      "version": [
                        "[3.3.7, 3.4.10)",
                        "[3.5,3.5.3)"
                      ]
                    }
                  ],
                  "from": [
                    "org.apache.zookeeper:zookeeper@3.5"
                  ],
                  "package": "org.apache.zookeeper:zookeeper",
                  "version": "3.5",
                  "severity": "high",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[3.4.6, 3.4.10)",
                      "[3.5.0-alpha, 3.5.3-beta)"
                    ]
                  },
                  "publicationTime": "2017-05-21T07:52:38Z",
                  "disclosureTime": "2017-02-15T06:56:48Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2017-5637"
                    ],
                    "CWE": [
                      "CWE-400"
                    ]
                  },
                  "credit": [
                    "Unknown"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                  "cvssScore": 7.5,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.zookeeper:zookeeper@3.5.5"
                  ]
                },
                {
                  "id": "SNYK-JAVA-ORGAPACHEZOOKEEPER-32301",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEZOOKEEPER-32301",
                  "title": "Authentication Bypass",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.zookeeper:zookeeper](http://zookeeper.apache.org/) is a centralized service for maintaining configuration information, naming, providing distributed synchronization, and providing group services.\n\n\nAffected versions of this package are vulnerable to Authentication Bypass.\nNo authentication/authorization is enforced when a server attempts to join a quorum, as a result an arbitrary end point could join the cluster and begin propagating counterfeit changes to the leader.\n\n## Remediation\n\nUpgrade `org.apache.zookeeper:zookeeper` to version 3.4.10, 3.5.4-beta or higher.\n\n\n## References\n\n- [Apache Mail Archives](https://lists.apache.org/thread.html/c75147028c1c79bdebd4f8fa5db2b77da85de2b05ecc0d54d708b393@%3Cdev.zookeeper.apache.org%3E)\n",
                  "functions": [],
                  "from": [
                    "org.apache.zookeeper:zookeeper@3.5"
                  ],
                  "package": "org.apache.zookeeper:zookeeper",
                  "version": "3.5",
                  "severity": "high",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[,3.4.10)",
                      "[3.5.0-alpha, 3.5.4-beta)"
                    ]
                  },
                  "publicationTime": "2018-05-22T13:32:24Z",
                  "disclosureTime": "2018-05-21T18:49:04Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2018-8012"
                    ],
                    "CWE": [
                      "CWE-592"
                    ]
                  },
                  "credit": [
                    "Foldi Tamas",
                    "Eugene Koontz"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                  "cvssScore": 7.5,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.zookeeper:zookeeper@3.5.5"
                  ]
                }
              ],
              "licenses": []
            },
            "dependencyCount": 8,
            "org": {
                "name": "mySnykOrganization",
                "id": "b94596b8-9d3e-45ae-ac1d-2bf7fa83d848"
            },
            "licensesPolicy": null,
            "packageManager": "maven"
        }


## npm [/test/npm{?org}]
Test for issues in npm files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

### Test for issues in a public package by name and version  [GET /test/npm/{packageName}/{version}{?org}]
You can test `npm` packages for issues according to their name and version.

+ Parameters
    + packageName: `ms` (string, required) - The package name. For scoped packages, **must** be url-encoded, so to test "@angular/core" version 4.3.2, one should `GET /test/npm/%40angular%2Fcore/4.3.2`.
    + version: `0.7.0` (string, required) - The Package version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "npm:ms:20151024",
                "url": "https://snyk.io/vuln/npm:ms:20151024",
                "title": "Regular Expression Denial of Service (ReDoS)",
                "type": "vuln",
                "description": "## Overview\n\n[ms](https://www.npmjs.com/package/ms) is a tiny millisecond conversion utility.\n\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS)\nattack when converting a time period string (i.e. `\"2 days\"`, `\"1h\"`) into a milliseconds integer. A malicious user could pass extremely long strings to `ms()`, causing the server to take a long time to process, subsequently blocking the event loop for that extended period.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n\r\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n\r\nLet’s take the following regular expression as an example:\r\n```js\r\nregex = /A(B|C+)+D/\r\n```\r\n\r\nThis regular expression accomplishes the following:\r\n- `A` The string must start with the letter 'A'\r\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n- `D` Finally, we ensure this section of the string ends with a 'D'\r\n\r\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n\r\nIt most cases, it doesn't take very long for a regex engine to find a match:\r\n\r\n```bash\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD\")'\r\n0.04s user 0.01s system 95% cpu 0.052 total\r\n\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX\")'\r\n1.79s user 0.02s system 99% cpu 1.812 total\r\n```\r\n\r\nThe entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n\r\nMost Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n\r\nLet's look at how our expression runs into this problem, using a shorter string: \"ACCCX\". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n1. CCC\r\n2. CC+C\r\n3. C+CC\r\n4. C+C+C.\r\n\r\nThe engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n\r\nFrom there, the number of steps the engine must use to validate a string just continues to grow.\r\n\r\n| String | Number of C's | Number of steps |\r\n| -------|-------------:| -----:|\r\n| ACCCX | 3 | 38\r\n| ACCCCX | 4 | 71\r\n| ACCCCCX | 5 | 136\r\n| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n\r\n\r\nBy the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\n\n## Remediation\n\nUpgrade `ms` to version 0.7.1 or higher.\n\n\n## References\n\n- [OSS Security advisory](https://www.openwall.com/lists/oss-security/2016/04/20/11)\n\n- [OWASP - ReDoS](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)\n\n- [Security Focus](https://www.securityfocus.com/bid/96389)\n",
                "functions": [
                  {
                    "functionId": {
                      "filePath": "ms.js",
                      "functionName": "parse"
                    },
                    "version": [
                      ">0.1.0 <=0.3.0"
                    ]
                  },
                  {
                    "functionId": {
                      "filePath": "index.js",
                      "functionName": "parse"
                    },
                    "version": [
                      ">0.3.0 <0.7.1"
                    ]
                  }
                ],
                "from": [
                  "ms@0.7.0"
                ],
                "package": "ms",
                "version": "0.7.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<0.7.1"
                  ]
                },
                "publicationTime": "2015-11-06T02:09:36Z",
                "disclosureTime": "2015-10-24T20:39:59Z",
                "isUpgradable": true,
                "isPatchable": true,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-MS-10064"
                  ],
                  "CVE": [
                    "CVE-2015-8315"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "NSP": [
                    46
                  ]
                },
                "credit": [
                  "Adam Baldwin"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "cvssScore": 5.3,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:5",
                    "modificationTime": "2019-12-03T11:40:45.777474Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_5_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk5.patch"
                    ],
                    "version": "=0.1.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:4",
                    "modificationTime": "2019-12-03T11:40:45.776329Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_4_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk4.patch"
                    ],
                    "version": "=0.2.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:3",
                    "modificationTime": "2019-12-03T11:40:45.775292Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_3_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk3.patch"
                    ],
                    "version": "=0.3.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:2",
                    "modificationTime": "2019-12-03T11:40:45.774221Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_2_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk2.patch"
                    ],
                    "version": "<0.6.0 >0.3.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:1",
                    "modificationTime": "2019-12-03T11:40:45.773094Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_1_0_48701f029417faf65e6f5e0b61a3cebe5436b07b_snyk.patch"
                    ],
                    "version": "<0.7.0 >=0.6.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:ms:20151024:0",
                    "modificationTime": "2019-12-03T11:40:45.772009Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/ms/20151024/ms_20151024_0_0_48701f029417faf65e6f5e0b61a3cebe5436b07b.patch"
                    ],
                    "version": "=0.7.0"
                  }
                ],
                "upgradePath": [
                  "ms@0.7.1"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 1,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "npm"
        }


### Test package.json & package-lock.json File [POST /test/npm{?org}]
You can test your npm packages for issues according to their manifest file & optional lockfile using this action. It takes a JSON object containing a "target" `package.json` and optionally a `package-lock.json`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (npm request payload)


+ Response 200 (application/json; charset=utf-8)


        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "npm:node-uuid:20160328",
                "url": "https://snyk.io/vuln/npm:node-uuid:20160328",
                "title": "Insecure Randomness",
                "type": "vuln",
                "description": "## Overview\n[`node-uuid`](https://github.com/kelektiv/node-uuid) is a Simple, fast generation of RFC4122 UUIDS.\n\nAffected versions of this package are vulnerable to Insecure Randomness. It uses the cryptographically insecure `Math.random` which can produce predictable values and should not be used in security-sensitive context.\n\n## Remediation\nUpgrade `node-uuid` to version 1.4.4 or greater.\n\n## References\n- [GitHub Issue](https://github.com/broofa/node-uuid/issues/108)\n- [GitHub Issue 2](https://github.com/broofa/node-uuid/issues/122)\n",
                "functions": [],
                "from": [
                  "node-uuid@1.4.0"
                ],
                "package": "node-uuid",
                "version": "1.4.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.4.4"
                  ]
                },
                "publicationTime": "2016-03-28T22:00:02.566000Z",
                "disclosureTime": "2016-03-28T21:29:30Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-NODEUUID-10089"
                  ],
                  "CVE": [],
                  "CWE": [
                    "CWE-330"
                  ],
                  "NSP": [
                    93
                  ]
                },
                "credit": [
                  "Fedot Praslov"
                ],
                "CVSSv3": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "cvssScore": 4.2,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:node-uuid:20160328:0",
                    "modificationTime": "2019-12-03T11:40:45.815314Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/node-uuid/20160328/node-uuid_20160328_0_0_616ad3800f35cf58089215f420db9654801a5a02.patch"
                    ],
                    "version": "<=1.4.3 >=1.4.2"
                  }
                ],
                "upgradePath": [
                  "node-uuid@1.4.6"
                ]
              },
              {
                "id": "npm:qs:20140806",
                "url": "https://snyk.io/vuln/npm:qs:20140806",
                "title": "Denial of Service (Memory Exhaustion)",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Denial of Service (Memory Exhaustion).\nDuring parsing, the `qs` module may create a sparse area (an array where no elements are filled), and grow that array to the necessary size based on the indices used on it. An attacker can specify a high index value in a query string, thus making the server allocate a respectively big array. Truly large values can cause the server to run out of memory and cause it to crash - thus enabling a Denial-of-Service attack.\n\n## Remediation\n\nUpgrade `qs` to version 1.0.0 or higher.\n\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## References\n\n- [GitHub Commit](https://github.com/tj/node-querystring/pull/114/commits/43a604b7847e56bba49d0ce3e222fe89569354d8)\n\n- [GitHub Issue](https://github.com/visionmedia/node-querystring/issues/104)\n\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2014-7191)\n",
                "functions": [
                  {
                    "functionId": {
                      "filePath": "index.js",
                      "functionName": "compact"
                    },
                    "version": [
                      "<1.0.0"
                    ]
                  }
                ],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.0.0"
                  ]
                },
                "publicationTime": "2014-08-06T06:10:22Z",
                "disclosureTime": "2014-08-06T06:10:22Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10019"
                  ],
                  "CVE": [
                    "CVE-2014-7191"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "NSP": [
                    29
                  ]
                },
                "credit": [
                  "Dustin Shiver"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806:0",
                    "modificationTime": "2019-12-03T11:40:45.741062Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806/qs_20140806_0_0_43a604b7847e56bba49d0ce3e222fe89569354d8_snyk.patch"
                    ],
                    "version": "<1.0.0 >=0.6.5"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806:1",
                    "modificationTime": "2019-12-03T11:40:45.728930Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806/qs_20140806_0_1_snyk_npm.patch"
                    ],
                    "version": "=0.5.6"
                  }
                ],
                "upgradePath": [
                  "qs@1.0.0"
                ]
              },
              {
                "id": "npm:qs:20140806-1",
                "url": "https://snyk.io/vuln/npm:qs:20140806-1",
                "title": "Denial of Service (Event Loop Blocking)",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Denial of Service (Event Loop Blocking).\nWhen parsing a string representing a deeply nested object, qs will block the event loop for long periods of time. Such a delay may hold up the server's resources, keeping it from processing other requests in the meantime, thus enabling a Denial-of-Service attack.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\n\nUpgrade `qs` to version 1.0.0 or higher.\n\n\n## References\n\n- [Node Security Advisory](https://nodesecurity.io/advisories/28)\n",
                "functions": [],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.0.0"
                  ]
                },
                "publicationTime": "2014-08-06T06:10:23Z",
                "disclosureTime": "2014-08-06T06:10:23Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10020"
                  ],
                  "CVE": [
                    "CVE-2014-10064"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "NSP": [
                    28
                  ]
                },
                "credit": [
                  "Tom Steele"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                "cvssScore": 6.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806-1:1",
                    "modificationTime": "2019-12-03T11:40:45.744535Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806-1/qs_20140806-1_0_1_snyk.patch"
                    ],
                    "version": "=0.5.6"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806-1:0",
                    "modificationTime": "2019-12-03T11:40:45.742148Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806-1/qs_20140806-1_0_0_snyk.patch"
                    ],
                    "version": "<1.0.0 >=0.6.5"
                  }
                ],
                "upgradePath": [
                  "qs@1.0.0"
                ]
              },
              {
                "id": "npm:qs:20170213",
                "url": "https://snyk.io/vuln/npm:qs:20170213",
                "title": "Prototype Override Protection Bypass",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Prototype Override Protection Bypass.\nBy default `qs` protects against attacks that attempt to overwrite an object's existing prototype properties, such as `toString()`, `hasOwnProperty()`,etc.\r\n\r\nFrom [`qs` documentation](https://github.com/ljharb/qs):\r\n> By default parameters that would overwrite properties on the object prototype are ignored, if you wish to keep the data from those fields either use plainObjects as mentioned above, or set allowPrototypes to true which will allow user input to overwrite those properties. WARNING It is generally a bad idea to enable this option as it can cause problems when attempting to use the properties that have been overwritten. Always be careful with this option.\r\n\r\nOverwriting these properties can impact application logic, potentially allowing attackers to work around security controls, modify data, make the application unstable and more.\r\n\r\nIn versions of the package affected by this vulnerability, it is possible to circumvent this protection and overwrite prototype properties and functions by prefixing the name of the parameter with `[` or `]`. e.g. `qs.parse(\"]=toString\")` will return `{toString = true}`, as a result, calling `toString()` on the object will throw an exception.\r\n\r\n**Example:**\r\n```js\r\nqs.parse('toString=foo', { allowPrototypes: false })\r\n// {}\r\n\r\nqs.parse(\"]=toString\", { allowPrototypes: false })\r\n// {toString = true} <== prototype overwritten\r\n```\r\n\r\nFor more information, you can check out our [blog](https://snyk.io/blog/high-severity-vulnerability-qs/).\r\n\r\n## Disclosure Timeline\r\n- February 13th, 2017 - Reported the issue to package owner.\r\n- February 13th, 2017 - Issue acknowledged by package owner.\r\n- February 16th, 2017 - Partial fix released in versions `6.0.3`, `6.1.1`, `6.2.2`, `6.3.1`.\r\n- March 6th, 2017     - Final fix released in versions `6.4.0`,`6.3.2`, `6.2.3`, `6.1.2` and `6.0.4`\n\n## Remediation\n\nUpgrade `qs` to version 6.0.4, 6.1.2, 6.2.3, 6.3.2 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d)\n\n- [Report of an insufficient fix](https://github.com/ljharb/qs/issues/200)\n",
                "functions": [
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "internals.parseObject"
                    },
                    "version": [
                      "<6.0.4"
                    ]
                  },
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "parseObject"
                    },
                    "version": [
                      ">=6.2.0 <6.2.3",
                      "6.3.0"
                    ]
                  },
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "parseObjectRecursive"
                    },
                    "version": [
                      ">=6.3.1 <6.3.2"
                    ]
                  }
                ],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<6.0.4",
                    ">=6.1.0 <6.1.2",
                    ">=6.2.0 <6.2.3",
                    ">=6.3.0 <6.3.2"
                  ]
                },
                "publicationTime": "2017-03-01T10:00:54Z",
                "disclosureTime": "2017-02-13T00:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10407"
                  ],
                  "CVE": [
                    "CVE-2017-1000048"
                  ],
                  "CWE": [
                    "CWE-20"
                  ]
                },
                "credit": [
                  "Snyk Security Research Team"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:7",
                    "modificationTime": "2019-12-03T11:40:45.862615Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/603_604.patch"
                    ],
                    "version": "=6.0.3"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:6",
                    "modificationTime": "2019-12-03T11:40:45.861504Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/602_604.patch"
                    ],
                    "version": "=6.0.2"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:5",
                    "modificationTime": "2019-12-03T11:40:45.860523Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/611_612.patch"
                    ],
                    "version": "=6.1.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:4",
                    "modificationTime": "2019-12-03T11:40:45.859411Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/610_612.patch"
                    ],
                    "version": "=6.1.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:3",
                    "modificationTime": "2019-12-03T11:40:45.858334Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/622_623.patch"
                    ],
                    "version": "=6.2.2"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:2",
                    "modificationTime": "2019-12-03T11:40:45.857318Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/621_623.patch"
                    ],
                    "version": "=6.2.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:1",
                    "modificationTime": "2019-12-03T11:40:45.856271Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/631_632.patch"
                    ],
                    "version": "=6.3.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:0",
                    "modificationTime": "2019-12-03T11:40:45.855245Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/630_632.patch"
                    ],
                    "version": "=6.3.0"
                  }
                ],
                "upgradePath": [
                  "qs@6.0.4"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 2,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "npm"
        }



## dep [/test/golangdep{?org}]
Test for issues in Go dep files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.


### Test Gopkg.toml & Gopkg.lock File [POST /test/golangdep{?org}]
You can test your Go dep packages for issues according to their manifest file & lockfile using this action. It takes a JSON object containing a "target" `Gopkg.toml` and a `Gopkg.lock`.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (golangdep request payload)


+ Response 200 (application/json; charset=utf-8)

        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-GOLANG-GITHUBCOMSATORIGOUUID-72488",
                  "url": "http://localhost:34612/vuln/SNYK-GOLANG-GITHUBCOMSATORIGOUUID-72488",
                  "title": "Insecure Randomness",
                  "type": "vuln",
                  "description": "## Overview\n[github.com/satori/go.uuid](https://github.com/satori/go.uuid) provides pure Go implementation of Universally Unique Identifier (UUID).\r\n\r\nAffected versions of this package are vulnerable to Insecure Randomness producing predictable `UUID` identifiers due to the limited number of bytes read when using the `g.rand.Read` function.\r\n \r\n## Disclosure Timeline\r\n* Jun 3th, 2018 - The vulnerability introduced by replacing the function `rand.Read()` with the function `g.rand.Read()` (https://github.com/satori/go.uuid/commit/0ef6afb2f6cdd6cdaeee3885a95099c63f18fc8c)\r\n* Mar 23th, 2018- An issue was reported.\r\n* Oct 16th, 2018 Issue fixed\r\n\r\n## Remediation\r\nA fix was merged into the master branch but not yet published.\n\n## References\n- [GitHub Commit](https://github.com/satori/go.uuid/commit/d91630c8510268e75203009fe7daf2b8e1d60c45)\n- [Github Issue](https://github.com/satori/go.uuid/issues/73)\n",
                  "functions": [],
                  "from": [
                    "github.com/satori/go.uuid@v1.2.0"
                  ],
                  "package": "github.com/satori/go.uuid",
                  "version": "v1.2.0",
                  "severity": "high",
                  "exploitMaturity": "no-known-exploit",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "hashesRange": [
                      ">=0ef6afb2f6cdd6cdaeee3885a95099c63f18fc8c <d91630c8510268e75203009fe7daf2b8e1d60c45"
                    ],
                    "vulnerable": [
                      "=1.2.0"
                    ],
                    "vulnerableHashes": [
                      "c596ec57260fd2ad47b2ae6809d6890a2f99c3b2",
                      "36e9d2ebbde5e3f13ab2e25625fd453271d6522e",
                      "f6920249aa08fc2a2c2e8274ea9648d0bb1e9364",
                      "0ef6afb2f6cdd6cdaeee3885a95099c63f18fc8c"
                    ]
                  },
                  "publicationTime": "2018-10-24T08:56:41Z",
                  "disclosureTime": "2018-03-23T08:57:24Z",
                  "isUpgradable": false,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [],
                    "CWE": [
                      "CWE-338"
                    ]
                  },
                  "credit": [
                    "josselin-c"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvssScore": 8.1,
                  "patches": [],
                  "upgradePath": []
                }
              ],
              "licenses": [
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/json/token@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/json/token",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/json/scanner@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/json/scanner",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/json/parser@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/json/parser",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/token@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/token",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/strconv@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/strconv",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/scanner@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/scanner",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/printer@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/printer",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/parser@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/parser",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl/hcl/ast@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl/hcl/ast",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                },
                {
                  "id": "snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "url": "http://localhost:34612/vuln/snyk:lic:golang:github.com:hashicorp:hcl:MPL-2.0",
                  "title": "MPL-2.0 license",
                  "type": "license",
                  "from": [
                    "github.com/hashicorp/hcl@v1.0.0"
                  ],
                  "package": "github.com/hashicorp/hcl",
                  "version": "v1.0.0",
                  "severity": "medium",
                  "language": "golang",
                  "packageManager": "golang",
                  "semver": {
                    "vulnerable": [
                      ">=0"
                    ],
                    "vulnerableHashes": [
                      "*"
                    ]
                  }
                }
              ]
            },
            "dependencyCount":101,
            "org":{
                "name":"atokeneduser",
                "id":"689ce7f9-7943-4a71-b704-2ba575f01089"
            },
            "licensesPolicy": null,
            "packageManager": "golangdep"
        }

## vendor [/test/govendor{?org}]
Test for issues in Go vendor files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.


### Test vendor.json File [POST /test/govendor{?org}]
You can test your Go vendor packages for issues according to their manifest file using this action. It takes a JSON object containing a "target" `vendor.json`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (govendor request payload)


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-GOLANG-GITHUBCOMDOCKERLIBCONTAINER-50012",
                "url": "https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDOCKERLIBCONTAINER-50012",
                "title": "Symlink Attack",
                "type": "vuln",
                "description": "## Overview\nAffected version of [`github.com/docker/libcontainer`](https://github.com/docker/libcontainer) are vulnerable to Symlink Attacks.\nLibcontainer and Docker Engine before 1.6.1 opens the file-descriptor passed to the pid-1 process before performing the chroot, which allows local users to gain privileges via a symlink attack in an image.\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-3627)\n- [GitHub Commit](https://github.com/docker/libcontainer/commit/46132cebcf391b56842f5cf9b247d508c59bc625)\n- [Packetstorm Security](http://packetstormsecurity.com/files/131835/Docker-Privilege-Escalation-Information-Disclosure.html)\n- [Seclists](http://seclists.org/fulldisclosure/2015/May/28)\n- [Docker Security Advisory](https://groups.google.com/forum/#%21searchin/docker-user/1.6.1/docker-user/47GZrihtr-4/nwgeOOFLexIJ)\n",
                "functions": [],
                "from": [
                  "github.com/docker/libcontainer@v1.4.0"
                ],
                "package": "github.com/docker/libcontainer",
                "version": "v1.4.0",
                "severity": "critical",
                "exploitMaturity": "no-known-exploit",
                "language": "golang",
                "packageManager": "golang",
                "semver": {
                  "hashesRange": [
                    ">=5c246d038fc47b8d57a474e1b212ffe646764ee9 <46132cebcf391b56842f5cf9b247d508c59bc625"
                  ],
                  "vulnerable": [
                    "<1.6.1"
                  ],
                  "vulnerableHashes": [
                    "cab4b9bce1bece1b6c575e1826f3e5b221faebf3",
                    "4a72e540feb67091156b907c4700e580a99f5a9d",
                    "eb74393a3d2daeafbef4f5f27c0821cbdd67559c",
                    "4332ffcfc6765245e8e9151a2907b0e4b76f218f",
                    "7eceabd47f41328d6e894418ae167ce8377bda22",
                    "ecace12e5a3e309d82c5b3b1548a3251b3bc4e2a",
                    "afb167a417ed8379c008b070fb5c0b1bc84bbcba",
                    "2b4512809110033e5ec532167efd6fabf2dd596d",
                    "c2403c32dbf8a67870ab2ba7524c117fc0652256",
                    "4077c254a6ac99930d720a9b95709dbd2614bc61",
                    "1b755bf962ec1d29e9e5e66e2cc15704fac088e7",
                    "1c9de5b4d21b94499a1e91c9b94ba06831ac5393",
                    "e3184f97e040c3121502dc382d41ac58a98b685a",
                    "0dee9793d5efd9842a2e8890fa0f8981d20b196e",
                    "3e9299d6da5749b263fc3dc93d50b5c854fa199c",
                    "152107f44ae9e38b38609fdbc75ac6f9f56c4fed",
                    "623fe598e4d5e75e70440f45298eecec414788b3",
                    "e30793aed7a30772054abfb1b3f3f703f119b55b",
                    "0596e6384a586223c56c5ea7d14467ebf5d17247",
                    "42fed751fbab3f340461d06edb896cd10cd49812",
                    "e451df796aaa605413a0b84ddd1bf39ec4a751a0",
                    "b0eece8d7d945e1e7fc98c2ae3b7dd0a860a7c2a",
                    "5c246d038fc47b8d57a474e1b212ffe646764ee9",
                    "bfa67ab988f434fd6836c1868eb5d7d1d7864e8a",
                    "9bebc660423ca974192599a6a5ea8e016a6fe1fc",
                    "e22b58954324b3593737438032412f15ed9602e9",
                    "af371eae767ceb51b8804f212bf97584d876feb3",
                    "f61899ece3fc1da206a0eb28fada0595ab381887",
                    "0d0402712b5a13d1b54a345a63ec67982e2e0089",
                    "d1ae7cd67310f482af22de3abeb26d28e65274bf",
                    "9f2c67332f48c0050846ac86e01cb5dadbd1d8fe",
                    "62bdfc482d8edaa618b544fb2beafdf0c44dce5e",
                    "699429e60f23ab0fa3bdd97b6326316be08791ad",
                    "35c01f9eb3c228201a3fc5d2301d1fc7a00bde13",
                    "a72f710d89eaabf23dad7c084082bccb26e6336f",
                    "eb84dd1b73df035e6e64c8513daaa476c72dedfc",
                    "5b73860e65598203b26d57aabc96ae0f52c9f9ab",
                    "d64cfe5c05448935c75c92f65d604c751bbf5153",
                    "62626677876330d60fe3512f59f1fd8f82799ca5",
                    "43842efeccbd8077dba8f85fc9e772e0647b82cb",
                    "d6cd7ce43faa53d212052dbbcf209029ec2ec951",
                    "ebefcddc3c4b99ae312ac575c288856e177ed6ef",
                    "83add60f217d32561ff0ff62ebf1d6db6a2a11a3",
                    "14af6755f04233fbe55cb354a9351fe05afd43a0",
                    "8530167f7f5b5eb329f5377b6b74a904482a10ed",
                    "000d36e109f5d04bad5342bb779e02b2b9b252f7",
                    "1db687f4f480c06e6cadfdb0971985df4313ddc7",
                    "689e8ec9493a4294856dc1568f5ef667e106707c",
                    "0eb8a1aac3d903b3c7925208c34f09c02910e7aa",
                    "edb31ce0a6fd7956bffc0829000c60bdd56b9f32",
                    "53fce307557cbffdbc54647ef63956b2cb0cee86",
                    "c22d5c90cf907f4f34d2bc13cad9c82a7fce9077",
                    "ef1c1c4289559e818d3ec77ce9c1b6a77d2ac764",
                    "2da44f8c7b703f87e9c07164c9cc1cdd31031783",
                    "ee102305fb35a23668136b102ed4d0dd5b3d9ce5",
                    "3ca0e1ff95c54577c65b5fbb734c267c23782974",
                    "f115a5f6c8c2a3cc6340408e6644236a88dcaad0",
                    "29ba9b3179d014cc87129af5c51b1263443f387b",
                    "c1ca18404fa63209e0a65abf443669155991b4df",
                    "5bb81469895d669ddcb4b49e83809a980d57d6b1",
                    "6feb7bda04b3130e81cf9606ddb7a156d4a63f7a",
                    "7c8550af53b4d428d8f3a7c19c0c4a8ebca8ff21",
                    "7766c1e07bd49fdc290f0557268950d35b867823",
                    "4903df2ed52a01f08626739ad35937752de82a09",
                    "58feafa848d9657dda34e5ccc3a196e359566bda",
                    "9e787db1b108941edab18209a7468e6c555002ce",
                    "e7953c3609b62a25b0bfedcd9d3885ca1b99d2fb",
                    "8c3b6b18689796bc9625258258e8664746b24e85",
                    "dd3cb8822352fd4acc0b8b426bd86e47e98f6853",
                    "cc524f1b729cb5d7592d0a0b07cb3ff1fe6eda98",
                    "c22ac4876f0a218584ae862900f3058470be38a3",
                    "c1fb904d1047359e8c4dadafaa0ab065efe9e03e",
                    "1f176f3c0dae283d66df5360de8a93ec14b4fbd0",
                    "50f0faa795dc62773857a0cc3cfb6d5681ba3562",
                    "3fbf1856025f54b6eab6e73b7ff8aa4d1020e1c1",
                    "f4a4391e4ef7e886e56816ae59cbe99d8cff91d9",
                    "2d9ef3af72e89ad9df164bd0f435371aa4fa0dea",
                    "187792e35bb47c89fdfe34409162c814627daacc",
                    "b322073f27b0e9e60b2ab07eff7f4e96a24cb3f9",
                    "f78bf211f023d28392c6aa0d1934bb1001b3a180",
                    "20af7e70e2511b4da0e035bf2fa2d6295f198970",
                    "f8eb40433c4a8617a20ad36119973af6f9dd2cd0",
                    "d7dea0e925315bab640115053204c16718839b1e",
                    "295c70865d10d7c57ba13cbef45c1d276ebfa83e",
                    "5a87153824b838be92503b57e76e96519b84b522",
                    "fec4c5ab0a75d7e6a46955bda0818bed7f8fecf3",
                    "6a76ecb1ce53d9e623826b238033b86f072395a9",
                    "2c037b7fd98e1c03e0c67ceccfd8e3300457e07e",
                    "4ce8d973204ebace2970c662f6f841ab11a3cc13",
                    "870119e763b5976d7331fbd8656ed65207ba95ad",
                    "58fc93160e03387a4f41dcf4aed2e376c4a92db4",
                    "a3b0209cc61301941810e54bc3678ccff9af71c1",
                    "ec005e73b9169d17651618b91836a5d86eb7b24c",
                    "2fac2dad91e390acb8937ede6154c265b7011cf9",
                    "0195469398f4fc1d42c0c20172b51e03ccf9ff1a",
                    "8d0b06257ba659ee91fa3862ed358cecbee37f73",
                    "6516e6ce8c7c71e44f95332ef740ea4082cfee39",
                    "55d61e22c5e0e4dc00c99847ba20a8ffa1e3a3d4",
                    "ca73d7aede7eaa05f4a0acb4bd5cb17a9408cd27",
                    "43fabe36d18fa36326d9e5efd2cca8b9376a7fdf",
                    "c06f92353f4f74cdb1c66ee0bbae1cdbb46934ce",
                    "d6fae7bb26807a386f5dd9a1ec2dc5ac51c24498",
                    "bde8bf2ebc5630399c7d0965f58b502100180400",
                    "444cc2989aca50986b45a56bfd8a32bd7ea23c1c",
                    "f5dfd9a702ad163be35023fe08c9573a614d6121",
                    "6c2f20eeeca488b98a613e013712d7c9a3d1e619",
                    "cc42996625afaf38d281f2457b08551a3df0d7bc",
                    "903680701ad5cf25484d0ac3e78152807dfa90b3",
                    "69228248334a576549a9af9df389b3cbfe0c211c",
                    "6460fd79667466d2d9ec03f77f319a241c58d40b",
                    "7d9244eab20fc96230636a066f88ad5165c34bc7",
                    "9387ebb6ba5fca526aedb54c7df684102639caa3",
                    "b21b19e0607582cceb8d715b85d27ec113a0b799",
                    "c4821b6f3e0a41af6bf3ed1cfa168c13381b9554",
                    "397b675315d00a34a09f058dd7e462af6f715da3",
                    "c504f85aabbff0d7380ca9da3f6051c56905c7c0",
                    "0f8f0601ae5668510ab7bde03041dafd39b18ec6",
                    "c3ab8d0cb4b439b7691edf7b63fcecd169834250",
                    "22df5551ed7367eb9cbb0cc22aea46351d2495ad",
                    "d284fdfaa36d37cbba5749562d6f9303ebab7d2f",
                    "a9a503082e492575be352c9c82040c1f4ed468d1",
                    "5fedffd8fd387b24b25186622c9566325ab3db1b",
                    "dc827aa0ee51829d292524fdf3a7a163feadabe2",
                    "f925aa3503eeba9d372c74d1fe2b17c8ecd97960",
                    "bc1d229dbe94a0100f4530b47e9c918f27b8cecd",
                    "71a57166c1209103dcd4355d21c161bd0f09e481",
                    "a9644c209f7764f9155db0c4aeb4f690c0cdb585",
                    "bcfdee970e8a32d04b472cd2c5712e10a5e425fe",
                    "3c474b9e2aad7c577faefca6c35a8512140c0c65",
                    "c34b3d5ce90a6b2828d5b97f553f4b49f64081af",
                    "286fffa4eeda7745f3b36dc938dae3e155d1b204",
                    "d1f0d5705debbe4d4b1aed7e087d5c49300eb271",
                    "08fdb50b03dc810ca8c4386f4f8271a8d51d4445",
                    "c44ab12c86689065978950d2ed92bb131b2a932c",
                    "5df859ad240af502aebef01ca28da3ef24951e05",
                    "ef4efd065cb6c136c7fcbdd65285cff549b745ac",
                    "2f1b2ce204490854938fab57142b557caa4ab66d",
                    "a36d471a0ef4e119ecfb41257aad246464024a40",
                    "83663f82e3d76f57ea57faf80b8fd7eb96933b9b",
                    "e8f5b543010eb0db146fd2593284ed19af93eccd",
                    "c8512754166539461fd860451ff1a0af7491c197",
                    "dc4c502efd85727abfed95af7789caa7f10d020d",
                    "4940cee052ece5a8b2ea477699e7bb232de1e1f8",
                    "025e6be6c5dc3d535286461088416afa74c42927",
                    "b4cda7a6cabf1966daf67f291c2c41ff9a1369f4",
                    "074441b495052c456f4b96524bd7a80d00db42e8",
                    "5847aacb32742fd734fa2c0584cae65636bba370",
                    "f9590b0927744d22ad0e1b737eecd07a48bb4c2f",
                    "e05f807a8936b4491632290f13958ca26d0aaace",
                    "fd0087d3acdc4c5865de1829d4accee5e3ebb658",
                    "38f729e577e07b2c3333ed4b04146e1d64f665a8",
                    "8a8eb57746e5372080a5f5e5b6fb9dce178c8220",
                    "afa8443118347a1f909941aec2732039d28a9034",
                    "d6eb76f8a2184688489fc3a611d80de36ef50877",
                    "0f397d4e145fb4053792d42b3424dd2143fb23ad",
                    "ba613c5a847ff30d312726eeff444714f8e31cde",
                    "445bebc1b16b1f2646a3cae841fe0e1266d79ada",
                    "e2ed997ae5b675fc8e78e7d0f9e6918c8b87503c",
                    "3b95acdfa1e54de15cae2fc3083147a185a31792",
                    "cacc15360ec04abb4c45f918e83bf33203946e32",
                    "09809b551ce9f05e96fc3055ae7a23329604415b",
                    "2a9511a0266afd48251609a03533094afe22fce2",
                    "b6cf7a6c8520fd21e75f8b3becec6dc355d844b0",
                    "fc3981ea5c10fb21cae6d6a8e78755be5b169999",
                    "dc34fe188385f42198997f6aedc170487c57c7eb",
                    "e9f8f8528abef64b8e1b8bc046a008b009ab2417",
                    "fe9f7668957641a404b0d2c8850f104df591e7f2",
                    "8da9c6878fa29f33dcfd74b1146d457a576d738a",
                    "4622c8ac9541790365eda22b6ce65d038f4026fe",
                    "3977c892e78d91a0c6d2a34fd2512a6c53c8d924",
                    "1bd146ed82f771395f991851f7d896d9ae778f3c",
                    "77085907a44039fe1cf9fe24d9c7675aa53d2f9b",
                    "107bad0ee5141bb847257a6f57dff2469dd584da",
                    "2da159823d0a54756308e73dc0e58a420daffad4",
                    "94fb37f5573e1484ba686b195079684cace18eb0",
                    "5c6332687d5d7c902cdd954e4e6a107ed6c60848",
                    "8b77eba9a6b506c71d1542d2fab1495249a7f7b6",
                    "da32455210de558c829f089e8c3a3d1ed8c34a5b",
                    "e1c14b3ca245fd06ef538005cd3a250904be5b4c",
                    "f0d1a8fc27830b899c5789ba2f80dfa9458792a4",
                    "846e522ffc157c12ba244c2c8a2c6adb1ed789f7",
                    "2a452c17aa2417cd89b5e25e8549f9e09c94a0dc",
                    "3cd416efe1e5b7d1679a20a91a73d757d481633b",
                    "e0de51f53c6b2711f39f4f29eb58b63a9ebf2c5c",
                    "f7837f4f717a9f09cf34fc325061ee8e38d1100a",
                    "13a5703d853fbd311e1fcfc5c95d459021781951",
                    "2aebf7d849e47ca927de332b82983ba8fe03d062",
                    "56bc1485df0ac0c2fe8ae5e0499e50a0580f2522",
                    "8d0f911e1d9265a8f362a7a16b893f7c40aee434",
                    "dc82e30089dbba31a1d0cf459321486a9b546fa0",
                    "4d863b7bd0d7da6ca1108031fd7d7997bf504496",
                    "73ba097bf596249068513559225d6e18c1767b47",
                    "da109f3af037352af24f935b1ea57ba8a7f26cad",
                    "3c52181f613353cc3b8aefbbf637c15a11cb8242",
                    "c96cde4e5db0da7e798e2712c2312f2468720a98",
                    "52a8c004ca94cf98f6866536de828c71eb42d1ec",
                    "b89112c542edcc9cf5af75694c16af28a3e4f12b",
                    "c099a20eb8bd084c17d9348bd0f6bef066ea514f",
                    "8067e34ec01588d2952d57e21c8c637fd3d3d114",
                    "9d4f6b3d3d4feba35ea13097be415bf099b670ce",
                    "334b1963711b743bf014502c5513a82a23eb65cc",
                    "190e50b08dbd72fd1d9f21f20581fa27a498481c",
                    "4c43b0f49880840966cb5df13abeeb19aa8e16d7",
                    "9946e299af9e911a54c83626f245dff20127e442",
                    "9825a26db570697e058a4580ec3b71ab3d82fc24",
                    "f8daab8a96fe2c73974073696d00deb4ffb40d47",
                    "88989e66d3a1ab960deb37f3dd7f824d85e1b9bc",
                    "c5eef904604b7e22083927bb99ea0c196d4cb8b9",
                    "4661c239dc6394aba960ba73144f2a7e3859537f",
                    "9303a8f15f6e55931a08542636922c1bf041ad52",
                    "9d91f080ced0bbfcbd3c003e2a20c9cdc81bc4ff",
                    "99233fde8c4f58853a474a5831ef0bcf6bf866c5",
                    "14a7d2f468404e25577dced6982248e80ddce79a",
                    "b6a1b889852cd6b365833ce2b04a0c1092867f75",
                    "5d6c507d7cfeff97172deedf3db13b5295bcacef",
                    "b89cd0cf5cf5deec2ed6fdc0d8ed4e4f3167aeb4",
                    "be02944484da197166020d6b3f08a19d7d7d244c",
                    "c37b9125ecaad0c100b6851baacf97adfa2339d6",
                    "045e9ae4a0fa8bff397b3c4f2614a3e609e6dd66",
                    "9744d72c740dd8cdfbb8cb4c58fb235355e0a0b4",
                    "74005ed4e0cdbc87ce40c6b79edfd599ba2355e9",
                    "1d7207079fc6ab5b2cbfedda3fc8993bc4441b02",
                    "8961fd20e6e213bf967db90166e24d38da065807",
                    "dd5576b2b3f5667811f882d1f64a11e13164791a",
                    "8600e6f3158bafe927706f0613c1520971d16c32",
                    "e9c1b0144ae784df9d26f59bfadd8cb2fc3a1d69",
                    "6423c8d2613e5130e9c37620773d2173c76f0acd",
                    "b48acf4613cc5347ca10b6d6edd6e1b94a5378c4",
                    "6c285c1d4964662ac64f0b98620d154caf423d79",
                    "312f997de638b8c18f92a59596a984bdb1a06a4e",
                    "11d14f2621370a527d2401c8bba10d2408819131",
                    "a6044b701c166fe538fc760f9e2dcea3d737cd2a",
                    "91a3f162afc90339b1d8f8d2f22d9c4271eddb84",
                    "54301f55934f42598b8f7c88effc4bd588e5f3e7",
                    "29f5cb6b391eea625c512df1f2ae7d9efccfbae9",
                    "087caf69e8cabd8f1f66f6239079b60172c9fb78",
                    "21ed4766b1523373b0463af497ef1c6b3b98c2ca",
                    "30b33064169e09e1c5daacb38ed461ed5820d0d2",
                    "a8a798a7c9b1da5beea8acfec16409d015ad85a7",
                    "a4f2e1e1878c1ce541aec24e6e2a690855cc8003",
                    "d06a2dab9f185c8cd2c21c0c97342cbdb7b9f38b",
                    "12a63757dbde3b0be25b49bc9e7625059088d319",
                    "35ae1c48710ff5a4db20645bc98c719cfb695b9a",
                    "85cd86999f70339509692b92cf182ec36697edcf",
                    "10d49f830b52ed05d9b41e18c8e1ff4a44a85fb3",
                    "3f35b26b8b2dcd856b12b985f9091260d5c5bd71",
                    "1a37242fa2af5db30ea72b95f948285efcd63d52",
                    "b49bd705dcddd496aedb6e797ce8691d276236af",
                    "eb2ae34c80f6b8ffb1bdfc55287d967c6e18cd81",
                    "39fbf0a90423a1e6e31c6c042acd9aea00793a18",
                    "d658fb8a2566cab11600af4db164c5f1f8656116",
                    "f4cf808a3d184c556a51cd53d98a2f4ea05acee4",
                    "bdff595cad6a42ba9675f99505bebecdb28209f0",
                    "9377591781a5346ed84517688787c305ed6554c4",
                    "19099e065da7c810f93e83d68c0776c2336e5e03",
                    "a1ac9b101571477a81e1cb3c6999f818bbbf0738",
                    "54968f68bc2ba50f59a66fba9f6823215a0bc4f6",
                    "9455a8ce3aaccceb4c282ef6c84d7edb36dd0d4c",
                    "21c344a479a8fd359a9c875f3056a7e72fe4d5fb",
                    "00abcf89d9ad026ddce4af0038db7953b01d8b8b",
                    "1a246dd54326124df57cb0e8e051f57abb549c9f",
                    "07db66a6ef857edee2c731d1b66f42a4f32d9622",
                    "d4867a6583c17001a60590684d91237a580e786a",
                    "46573774a27c7a4d20d508f1f07ba72d34616bc3",
                    "9184d9473d7b5ecb0dddca4052171534523602be",
                    "f6593810da73cf8e1cc982d9020850260fc1ff52",
                    "a9442e6660e71fd2058310e6155de3ef5e4f5fdf",
                    "cee97cb0ccad90c369b10d6a9512d678a0535cac",
                    "aaca2848a1e1eefa71ce2987b19abae2d34cf3aa",
                    "3125b53b1aef485ed2239d514b131ef80ad577c1",
                    "2990f254f030e62ab15b9399e26368aa3e291d15",
                    "b19b8a9677ae9e657e0195ac85a4849a67729cf6",
                    "e3b14402ebded2a7ec8f38809bf907ac72692ede",
                    "37d229d0262b6fa7dfb96184eff3f7882ddd487e",
                    "8002fd226367c0882973c69673bf8379df2fc198",
                    "a1c3e0db94579f59cc821132f958187339e68d88",
                    "4fdec5a8e10f95a5dbfd84cf382f2755f0342fda",
                    "ef73d7e235c4d4ab41402835193ac9ba0c4cc485",
                    "ad3d14f1da33d00ee3506f12922fb3faf87b65d7",
                    "a1d509759b9195a1c022f2eb9585b74d07a0f084",
                    "b7e54b0b41757cd36dd03fb29367b385c5fa3be0",
                    "d909440c48b7b64b016478de1e6ee78e2faa9e13",
                    "2ca9dc306e8c667eb9f00376898be52d8b980c88",
                    "031524c73df6fd40b13e89c44e86d4a62d77075b",
                    "6fae0d4fa68a85a1d552c5ae3140dd39f7a05c88",
                    "fb27b4238cd6c33bd899e240ead4b5fb8a2a24b1",
                    "0890cc54a92627c03119654c94c584a2e3c744ca",
                    "339edce03ed7fe59ec4a778abff243fa4cabaa23",
                    "2329014b6dbc473326291fa6e101e6d63c4dbd25",
                    "872663148e00c4d272fc67e8d369a5012ccbac5a",
                    "0e3b1262a168d51512014c4f7df6c37edce0f05d",
                    "606d9064b0a6abd82da3731fda9f1558ec1f153c",
                    "4bd39999a06fa1f710daae54c6cc8ca7d5784f58",
                    "562cd20d05e0427e6b18daa279a3a5f3b08c889d",
                    "4bbd44784c7c4eede8e53011a2c4981c16598d1f",
                    "dc4bd4cece9a6de7926e85a09f152fe4697a8bc5",
                    "770e2583907fa38e2b78601a90799b6ae7ab15eb",
                    "f34b3b765fb964dee979ac7646b6d609adbeb2ba",
                    "aa10040b570386c1ae311c6245b9e21295b2b83a",
                    "fff015f4094ab80ff2eb4978f8cdb3711187c50a",
                    "5b2be7d9d8444e0a5b706944c878cd0048ef026a",
                    "2cd0ee8cf21eecaa9d39d699692284be44cf6ca2",
                    "451043367be65468dd96bbf5868af666b25f1663",
                    "4fc29224cf362988a741dc07804225f730a326ec",
                    "dd6bc28afb3bafdde93ad7ed9f58b3a0aec2be99",
                    "1597c68f7b941fd97881155d7f077852e2914e7b",
                    "e59984353acde7207aa1115e261847bf4ddd9a8f",
                    "ee1000e153e1b7c8f223bb573bb8169d2033f4af",
                    "1d3b2589d734dc94a1719a3af40b87ed8319f329"
                  ]
                },
                "publicationTime": "2015-08-06T00:00:00Z",
                "disclosureTime": "2015-05-18T15:59:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-3627"
                  ],
                  "CWE": [
                    "CWE-59"
                  ]
                },
                "credit": [
                  "Tõnis Tiigi"
                ],
                "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 8.4,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 28,
          "org": {
            "name":"atokeneduser",
            "id":"689ce7f9-7943-4a71-b704-2ba575f01089"
          },
          "licensesPolicy": null,
          "packageManager": "govendor"
        }


## yarn [/test/yarn{?org}]
Test for issues in yarn files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

### Test package.json & yarn.lock File [POST /test/yarn{?org}]
You can test your yarn packages for issues according to their manifest file & lockfile using this action. It takes a JSON object containing a "target" `package.json` and a `yarn.lock`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (yarn request payload)


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "npm:node-uuid:20160328",
                "url": "https://snyk.io/vuln/npm:node-uuid:20160328",
                "title": "Insecure Randomness",
                "type": "vuln",
                "description": "## Overview\n[`node-uuid`](https://github.com/kelektiv/node-uuid) is a Simple, fast generation of RFC4122 UUIDS.\n\nAffected versions of this package are vulnerable to Insecure Randomness. It uses the cryptographically insecure `Math.random` which can produce predictable values and should not be used in security-sensitive context.\n\n## Remediation\nUpgrade `node-uuid` to version 1.4.4 or greater.\n\n## References\n- [GitHub Issue](https://github.com/broofa/node-uuid/issues/108)\n- [GitHub Issue 2](https://github.com/broofa/node-uuid/issues/122)\n",
                "functions": [],
                "from": [
                  "node-uuid@1.4.0"
                ],
                "package": "node-uuid",
                "version": "1.4.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.4.4"
                  ]
                },
                "publicationTime": "2016-03-28T22:00:02.566000Z",
                "disclosureTime": "2016-03-28T21:29:30Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-NODEUUID-10089"
                  ],
                  "CVE": [],
                  "CWE": [
                    "CWE-330"
                  ],
                  "NSP": [
                    93
                  ]
                },
                "credit": [
                  "Fedot Praslov"
                ],
                "CVSSv3": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "cvssScore": 4.2,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:node-uuid:20160328:0",
                    "modificationTime": "2019-12-03T11:40:45.815314Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/node-uuid/20160328/node-uuid_20160328_0_0_616ad3800f35cf58089215f420db9654801a5a02.patch"
                    ],
                    "version": "<=1.4.3 >=1.4.2"
                  }
                ],
                "upgradePath": [
                  "node-uuid@1.4.6"
                ]
              },
              {
                "id": "npm:qs:20140806",
                "url": "https://snyk.io/vuln/npm:qs:20140806",
                "title": "Denial of Service (Memory Exhaustion)",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Denial of Service (Memory Exhaustion).\nDuring parsing, the `qs` module may create a sparse area (an array where no elements are filled), and grow that array to the necessary size based on the indices used on it. An attacker can specify a high index value in a query string, thus making the server allocate a respectively big array. Truly large values can cause the server to run out of memory and cause it to crash - thus enabling a Denial-of-Service attack.\n\n## Remediation\n\nUpgrade `qs` to version 1.0.0 or higher.\n\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## References\n\n- [GitHub Commit](https://github.com/tj/node-querystring/pull/114/commits/43a604b7847e56bba49d0ce3e222fe89569354d8)\n\n- [GitHub Issue](https://github.com/visionmedia/node-querystring/issues/104)\n\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2014-7191)\n",
                "functions": [
                  {
                    "functionId": {
                      "filePath": "index.js",
                      "functionName": "compact"
                    },
                    "version": [
                      "<1.0.0"
                    ]
                  }
                ],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.0.0"
                  ]
                },
                "publicationTime": "2014-08-06T06:10:22Z",
                "disclosureTime": "2014-08-06T06:10:22Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10019"
                  ],
                  "CVE": [
                    "CVE-2014-7191"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "NSP": [
                    29
                  ]
                },
                "credit": [
                  "Dustin Shiver"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806:0",
                    "modificationTime": "2019-12-03T11:40:45.741062Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806/qs_20140806_0_0_43a604b7847e56bba49d0ce3e222fe89569354d8_snyk.patch"
                    ],
                    "version": "<1.0.0 >=0.6.5"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806:1",
                    "modificationTime": "2019-12-03T11:40:45.728930Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806/qs_20140806_0_1_snyk_npm.patch"
                    ],
                    "version": "=0.5.6"
                  }
                ],
                "upgradePath": [
                  "qs@1.0.0"
                ]
              },
              {
                "id": "npm:qs:20140806-1",
                "url": "https://snyk.io/vuln/npm:qs:20140806-1",
                "title": "Denial of Service (Event Loop Blocking)",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Denial of Service (Event Loop Blocking).\nWhen parsing a string representing a deeply nested object, qs will block the event loop for long periods of time. Such a delay may hold up the server's resources, keeping it from processing other requests in the meantime, thus enabling a Denial-of-Service attack.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\n\nUpgrade `qs` to version 1.0.0 or higher.\n\n\n## References\n\n- [Node Security Advisory](https://nodesecurity.io/advisories/28)\n",
                "functions": [],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<1.0.0"
                  ]
                },
                "publicationTime": "2014-08-06T06:10:23Z",
                "disclosureTime": "2014-08-06T06:10:23Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10020"
                  ],
                  "CVE": [
                    "CVE-2014-10064"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "NSP": [
                    28
                  ]
                },
                "credit": [
                  "Tom Steele"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                "cvssScore": 6.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806-1:1",
                    "modificationTime": "2019-12-03T11:40:45.744535Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806-1/qs_20140806-1_0_1_snyk.patch"
                    ],
                    "version": "=0.5.6"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20140806-1:0",
                    "modificationTime": "2019-12-03T11:40:45.742148Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20140806-1/qs_20140806-1_0_0_snyk.patch"
                    ],
                    "version": "<1.0.0 >=0.6.5"
                  }
                ],
                "upgradePath": [
                  "qs@1.0.0"
                ]
              },
              {
                "id": "npm:qs:20170213",
                "url": "https://snyk.io/vuln/npm:qs:20170213",
                "title": "Prototype Override Protection Bypass",
                "type": "vuln",
                "description": "## Overview\n\n[qs](https://www.npmjs.com/package/qs) is a querystring parser that supports nesting and arrays, with a depth limit.\n\n\nAffected versions of this package are vulnerable to Prototype Override Protection Bypass.\nBy default `qs` protects against attacks that attempt to overwrite an object's existing prototype properties, such as `toString()`, `hasOwnProperty()`,etc.\r\n\r\nFrom [`qs` documentation](https://github.com/ljharb/qs):\r\n> By default parameters that would overwrite properties on the object prototype are ignored, if you wish to keep the data from those fields either use plainObjects as mentioned above, or set allowPrototypes to true which will allow user input to overwrite those properties. WARNING It is generally a bad idea to enable this option as it can cause problems when attempting to use the properties that have been overwritten. Always be careful with this option.\r\n\r\nOverwriting these properties can impact application logic, potentially allowing attackers to work around security controls, modify data, make the application unstable and more.\r\n\r\nIn versions of the package affected by this vulnerability, it is possible to circumvent this protection and overwrite prototype properties and functions by prefixing the name of the parameter with `[` or `]`. e.g. `qs.parse(\"]=toString\")` will return `{toString = true}`, as a result, calling `toString()` on the object will throw an exception.\r\n\r\n**Example:**\r\n```js\r\nqs.parse('toString=foo', { allowPrototypes: false })\r\n// {}\r\n\r\nqs.parse(\"]=toString\", { allowPrototypes: false })\r\n// {toString = true} <== prototype overwritten\r\n```\r\n\r\nFor more information, you can check out our [blog](https://snyk.io/blog/high-severity-vulnerability-qs/).\r\n\r\n## Disclosure Timeline\r\n- February 13th, 2017 - Reported the issue to package owner.\r\n- February 13th, 2017 - Issue acknowledged by package owner.\r\n- February 16th, 2017 - Partial fix released in versions `6.0.3`, `6.1.1`, `6.2.2`, `6.3.1`.\r\n- March 6th, 2017     - Final fix released in versions `6.4.0`,`6.3.2`, `6.2.3`, `6.1.2` and `6.0.4`\n\n## Remediation\n\nUpgrade `qs` to version 6.0.4, 6.1.2, 6.2.3, 6.3.2 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d)\n\n- [Report of an insufficient fix](https://github.com/ljharb/qs/issues/200)\n",
                "functions": [
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "internals.parseObject"
                    },
                    "version": [
                      "<6.0.4"
                    ]
                  },
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "parseObject"
                    },
                    "version": [
                      ">=6.2.0 <6.2.3",
                      "6.3.0"
                    ]
                  },
                  {
                    "functionId": {
                      "filePath": "lib/parse.js",
                      "functionName": "parseObjectRecursive"
                    },
                    "version": [
                      ">=6.3.1 <6.3.2"
                    ]
                  }
                ],
                "from": [
                  "qs@0.0.6"
                ],
                "package": "qs",
                "version": "0.0.6",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "js",
                "packageManager": "npm",
                "semver": {
                  "vulnerable": [
                    "<6.0.4",
                    ">=6.1.0 <6.1.2",
                    ">=6.2.0 <6.2.3",
                    ">=6.3.0 <6.3.2"
                  ]
                },
                "publicationTime": "2017-03-01T10:00:54Z",
                "disclosureTime": "2017-02-13T00:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "ALTERNATIVE": [
                    "SNYK-JS-QS-10407"
                  ],
                  "CVE": [
                    "CVE-2017-1000048"
                  ],
                  "CWE": [
                    "CWE-20"
                  ]
                },
                "credit": [
                  "Snyk Security Research Team"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:7",
                    "modificationTime": "2019-12-03T11:40:45.862615Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/603_604.patch"
                    ],
                    "version": "=6.0.3"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:6",
                    "modificationTime": "2019-12-03T11:40:45.861504Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/602_604.patch"
                    ],
                    "version": "=6.0.2"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:5",
                    "modificationTime": "2019-12-03T11:40:45.860523Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/611_612.patch"
                    ],
                    "version": "=6.1.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:4",
                    "modificationTime": "2019-12-03T11:40:45.859411Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/610_612.patch"
                    ],
                    "version": "=6.1.0"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:3",
                    "modificationTime": "2019-12-03T11:40:45.858334Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/622_623.patch"
                    ],
                    "version": "=6.2.2"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:2",
                    "modificationTime": "2019-12-03T11:40:45.857318Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/621_623.patch"
                    ],
                    "version": "=6.2.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:1",
                    "modificationTime": "2019-12-03T11:40:45.856271Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/631_632.patch"
                    ],
                    "version": "=6.3.1"
                  },
                  {
                    "comments": [],
                    "id": "patch:npm:qs:20170213:0",
                    "modificationTime": "2019-12-03T11:40:45.855245Z",
                    "urls": [
                      "https://snyk-patches.s3.amazonaws.com/npm/qs/20170213/630_632.patch"
                    ],
                    "version": "=6.3.0"
                  }
                ],
                "upgradePath": [
                  "qs@6.0.4"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 2,
          "org": {
            "name":"atokeneduser",
            "id":"689ce7f9-7943-4a71-b704-2ba575f01089"
          },
          "licensesPolicy": null,
          "packageManager": "yarn"
        }


## rubygems [/test/rubygems{?org}]
Test for issues in rubygems packages and applications.

+ Parameters
    + org: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

### Test for issues in a public gem by name and version  [GET /test/rubygems/{gemName}/{version}{?org}]
You can test `rubygems` packages for issues according to their name and version.

+ Parameters
    + gemName: `rails-html-sanitizer` (string, required) - The gem name.
    + version: `1.0.3` (string, required) - The gem version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.


+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-RUBY-RAILSHTMLSANITIZER-22025",
                "url": "https://snyk.io/vuln/SNYK-RUBY-RAILSHTMLSANITIZER-22025",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n[rails-html-sanitizer](https://github.com/rails/rails-html-sanitizer)\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS). The gem allows non-whitelisted attributes to be present in sanitized output when input with specially-crafted HTML fragments, and these attributes can lead to an XSS attack on target applications.\n\nThis issue is similar to [CVE-2018-8048](https://snyk.io/vuln/SNYK-RUBY-LOOFAH-22023) in Loofah.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n\n## Remediation\nUpgrade `rails-html-sanitizer` to version 1.0.4 or higher.\n\n## References\n- [Ruby on Rails Security Google Forum](https://groups.google.com/d/msg/rubyonrails-security/tP7W3kLc5u4/uDy2Br7xBgAJ)\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-3741)\n",
                "functions": [],
                "from": [
                  "rails-html-sanitizer@1.0.3"
                ],
                "package": "rails-html-sanitizer",
                "version": "1.0.3",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "<1.0.4"
                  ]
                },
                "publicationTime": "2018-03-27T07:42:10.777000Z",
                "disclosureTime": "2018-03-22T21:46:15.453000Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-3741"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Kaarlo Haikonen"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": [
                  "rails-html-sanitizer@1.0.4"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 5,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "rubygems"
        }


### Test gemfile.lock file [POST /test/rubygems{?org}]
You can test your rubygems applications for issues according to their lockfile using this action. It takes a JSON object containing a the "target" `Gemfile.lock`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (rubygems request payload)


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-RUBY-JSON-20000",
                "url": "https://snyk.io/vuln/SNYK-RUBY-JSON-20000",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\n\nThe [`json`](https://rubygems.org/gems/json) gem is a JSON implementation as a Ruby extension in C.\nAffected versions of this Gem contain an overflow condition. This is triggered when user-supplied input is not properly validated while handling specially crafted data. This can allow a remote attacker to cause a stack-based buffer overflow, resulting in a denial of service, or potentially allowing the [execution of arbitrary code](https://snyk.io/vuln/SNYK-RUBY-JSON-20209).\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## References\n- http://rubysec.com/advisories/OSVDB-101157\n",
                "functions": [],
                "from": [
                  "json@1.0.0"
                ],
                "package": "json",
                "version": "1.0.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "< 1.1.0"
                  ]
                },
                "publicationTime": "2007-05-20T21:00:00Z",
                "disclosureTime": "2007-05-20T21:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-400"
                  ],
                  "OSVDB": [
                    "OSVDB-101157"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "json@1.1.0"
                ]
              },
              {
                "id": "SNYK-RUBY-JSON-20060",
                "url": "https://snyk.io/vuln/SNYK-RUBY-JSON-20060",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\nThe [`json`](https://rubygems.org/gems/json) gem is a JSON implementation as a Ruby extension in C.\nAffected versions of this Gem are vulnerable to Denial of Service (DoS) attacks and unsafe object creation vulnerabilities. When parsing certain JSON documents, the JSON gem tricked into creating Ruby symbols in a target system.\n\n## Details\n\nWhen parsing certain JSON documents, the JSON gem can be coerced in to creating Ruby symbols in a target system.  Since Ruby symbols are not garbage collected, this can result in a denial of service attack.\n\nThe same technique can be used to create objects in a target system that act like internal objects.  These \"act alike\" objects can be used to bypass certain security mechanisms and can be used as a spring board for SQL injection attacks in Ruby on Rails.\n\nImpacted code looks like this:\n```js\nJSON.parse(user_input)\n```\nWhere the `user_input` variable will have a JSON document like this:\n```json\n{\"json_class\":\"foo\"}\n```\nThe JSON gem will attempt to look up the constant \"foo\".  Looking up this constant will create a symbol.\n\nIn JSON version 1.7.x, objects with arbitrary attributes can be created using JSON documents like this:\n```json\n{\"json_class\":\"JSON::GenericObject\",\"foo\":\"bar\"}\n```\nThis document will result in an instance of `JSON::GenericObject`, with the attribute \"foo\" that has the value \"bar\".  Instantiating these objects will result in arbitrary symbol creation and in some cases can be used to bypass security measures.\n\nPLEASE NOTE: this behavior *does not change* when using `JSON.load`.  `JSON.load` should *never* be given input from unknown sources.  If you are processing JSON from an unknown source, *always* use `JSON.parse`.\n\n## References\n- https://www.ruby-lang.org/en/news/2013/02/22/json-dos-cve-2013-0269/\n- https://gist.github.com/rsierra/4943505\n",
                "functions": [],
                "from": [
                  "json@1.0.0"
                ],
                "package": "json",
                "version": "1.0.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "< 1.7.7, >= 1.7",
                    "< 1.6.8, >= 1.6",
                    "< 1.5.5"
                  ]
                },
                "publicationTime": "2013-02-10T22:00:00Z",
                "disclosureTime": "2013-02-10T22:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-0269"
                  ],
                  "CWE": [
                    "CWE-400"
                  ],
                  "OSVDB": [
                    "OSVDB-90074"
                  ]
                },
                "credit": [
                  "Thomas Hollstegge",
                  "Ben Murphy"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": [
                  "json@1.5.5"
                ]
              },
              {
                "id": "SNYK-RUBY-JSON-20209",
                "url": "https://snyk.io/vuln/SNYK-RUBY-JSON-20209",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\n\nThe [`json`](https://rubygems.org/gems/json) gem is a JSON implementation as a Ruby extension in C.\n\nAffected versions of this Gem contain an overflow condition. This is triggered when user-supplied input is not properly validated while handling specially crafted data. This can allow a remote attacker to cause a stack-based buffer overflow, resulting in a [denial of service](https://snyk.io/vuln/SNYK-RUBY-JSON-20000), or potentially allowing the execution of arbitrary code.\n\n## References\n\n- http://rubysec.com/advisories/OSVDB-101157\n",
                "functions": [],
                "from": [
                  "json@1.0.0"
                ],
                "package": "json",
                "version": "1.0.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "< 1.1.0"
                  ]
                },
                "publicationTime": "2007-05-20T21:00:00Z",
                "disclosureTime": "2007-05-20T21:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-94"
                  ],
                  "OSVDB": [
                    "OSVDB-101157-1"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "json@1.1.0"
                ]
              },
              {
                "id": "SNYK-RUBY-RACK-538324",
                "url": "https://snyk.io/vuln/SNYK-RUBY-RACK-538324",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\n\n[rack](https://rack.github.io/) is a minimal, modular and adaptable interface for developing web applications in Ruby. By wrapping HTTP requests and responses in the simplest way possible, it unifies and distills the API for web servers, web frameworks, and software in between (the so-called middleware) into a single method call.\n\n\nAffected versions of this package are vulnerable to Information Exposure.\nAttackers may be able to find and hijack sessions by using timing attacks targeting the session id. Session ids are usually stored and indexed in a database that uses some kind of scheme for speeding up lookups of that session id. By carefully measuring the amount of time it takes to look up a session, an attacker may be able to find a valid session id and hijack the session.\n\n## Remediation\n\nUpgrade `rack` to version 1.6.12, 2.0.8 or higher.\n\n\n## References\n\n- [GitHub Fix Commit](https://github.com/rack/rack/commit/7fecaee81f59926b6e1913511c90650e76673b38)\n\n- [GitHub Security Advisory](https://github.com/rack/rack/security/advisories/GHSA-hrqr-hxpp-chr3)\n",
                "functions": [],
                "from": [
                  "redis-rack-cache@1.1",
                  "rack-cache@1.1",
                  "rack@2.0.1"
                ],
                "package": "rack",
                "version": "2.0.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "<1.6.12",
                    ">=2.0.0.alpha, <2.0.8"
                  ]
                },
                "publicationTime": "2019-12-19T20:24:49Z",
                "disclosureTime": "2019-12-18T20:24:49Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-16782"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Will Leinweber"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": [
                  "redis-rack-cache@1.1",
                  "rack-cache@1.1",
                  "rack@2.0.8"
                ]
              },
              {
                "id": "SNYK-RUBY-RACK-72567",
                "url": "https://snyk.io/vuln/SNYK-RUBY-RACK-72567",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[rack](https://rack.github.io/) is a minimal, modular and adaptable interface for developing web applications in Ruby. By wrapping HTTP requests and responses in the simplest way possible, it unifies and distills the API for web servers, web frameworks, and software in between (the so-called middleware) into a single method call.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nvia the `scheme` method on `Rack::Request`.\n\n## Remediation\n\nUpgrade `rack` to version 1.6.11, 2.0.6 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/rack/rack/commit/313dd6a05a5924ed6c82072299c53fed09e39ae7)\n\n- [Google Security Forum](https://groups.google.com/forum/#!msg/rubyonrails-security/GKsAFT924Ag/DYtk-Xl6AAAJ)\n\n- [RedHat Bugzilla Bug](https://bugzilla.redhat.com/show_bug.cgi?id=1646818)\n",
                "functions": [],
                "from": [
                  "redis-rack-cache@1.1",
                  "rack-cache@1.1",
                  "rack@2.0.1"
                ],
                "package": "rack",
                "version": "2.0.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "<1.6.11",
                    ">=2.0.0, <2.0.6"
                  ]
                },
                "publicationTime": "2018-11-06T16:08:37Z",
                "disclosureTime": "2018-08-22T15:56:49Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-16470"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Aaron Patterson"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": [
                  "redis-rack-cache@1.1",
                  "rack-cache@1.1",
                  "rack@2.0.6"
                ]
              },
              {
                "id": "SNYK-RUBY-RACKCACHE-20031",
                "url": "https://snyk.io/vuln/SNYK-RUBY-RACKCACHE-20031",
                "title": "HTTP Header Caching Weakness",
                "type": "vuln",
                "description": "## Overview\n[rack-cache](https://rubygems.org/gems/rack-cache) enables HTTP caching for Rack-based applications.\nAffected versions of this gem contain a flaw related to the rubygem caching sensitive HTTP headers. This will result in a weakness that may make it easier for an attacker to gain access to a user's session via a specially crafted header.\n\n## References\n- http://rubysec.com/advisories/CVE-2012-2671\n",
                "functions": [],
                "from": [
                  "redis-rack-cache@1.1",
                  "rack-cache@1.1"
                ],
                "package": "rack-cache",
                "version": "1.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "< 1.2"
                  ]
                },
                "publicationTime": "2012-06-05T21:00:00Z",
                "disclosureTime": "2012-06-05T21:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2012-2671"
                  ],
                  "CWE": [
                    "CWE-444"
                  ],
                  "OSVDB": [
                    "OSVDB-83077"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": [
                  "redis-rack-cache@1.2",
                  "rack-cache@1.2"
                ]
              },
              {
                "id": "SNYK-RUBY-REDISSTORE-20452",
                "url": "https://snyk.io/vuln/SNYK-RUBY-REDISSTORE-20452",
                "title": "Deserialization of Untrusted Data",
                "type": "vuln",
                "description": "## Overview\n[`redis-store`](https://rubygems.org/gems/redis-store) is a namespaced Rack::Session, Rack::Cache, I18n and cache Redis stores for Ruby web frameworks.\n\nAffected versions of the package are vulnerable to Deserialization of Untrusted Data.\n\n# Details\nSerialization is a process of converting an object into a sequence of bytes which can be persisted to a disk or database or can be sent through streams. The reverse process of creating object from sequence of bytes is called deserialization. Serialization is commonly used for communication (sharing objects between multiple hosts) and persistence (store the object state in a file or a database). It is an integral part of popular protocols like _Remote Method Invocation (RMI)_, _Java Management Extension (JMX)_, _Java Messaging System (JMS)_, _Action Message Format (AMF)_, _Java Server Faces (JSF) ViewState_, etc.\n\n_Deserialization of untrusted data_ ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), is when the application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, letting the attacker to control the state or the flow of the execution.\n\nAn attacker just needs to identify a piece of software that has both a vulnerable class on its path, and performs deserialization on untrusted data. Then all they need to do is send the payload into the deserializer, getting the command executed.\n\n## Remediation\nUpgrade `redis-store` to version 1.4.0 or higher.\n\n## References\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-1000248)\n- [GitHub PR](https://github.com/redis-store/redis-store/pull/290)\n- [GitHub Issue](https://github.com/redis-store/redis-store/issues/289)\n- [GitHub Commit](https://github.com/redis-store/redis-store/commit/e0c1398d54a9661c8c70267c3a925ba6b192142e)\n",
                "functions": [],
                "from": [
                  "redis-rack-cache@1.1",
                  "redis-store@1.1.0"
                ],
                "package": "redis-store",
                "version": "1.1.0",
                "severity": "critical",
                "exploitMaturity": "no-known-exploit",
                "language": "ruby",
                "packageManager": "rubygems",
                "semver": {
                  "vulnerable": [
                    "<1.4.0"
                  ]
                },
                "publicationTime": "2017-12-07T09:52:33.659000Z",
                "disclosureTime": "2017-08-10T21:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-1000248"
                  ],
                  "CWE": [
                    "CWE-502"
                  ]
                },
                "credit": [
                  "Dylan Katz"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 9.8,
                "patches": [],
                "upgradePath": [
                  "redis-rack-cache@2.0.2",
                  "redis-store@1.4.0"
                ]
              }
            ],
            "licenses": []
          },
          "dependencyCount": 6,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "rubygems"
        }



## Gradle [/test/gradle{?org,repository}]
Test for issues in Gradle files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

### Test for issues in a public package by group, name and version  [GET /test/gradle/{group}/{name}/{version}{?org,repository}]
You can test `gradle` packages for issues according to their group, name and version. This is done via the maven endpoint (for Java), since the packages are hosted on maven central or a compatible repository. See "Maven" above for details.

+ Parameters
    + group: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + name: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.


+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY


+ Response 200 (application/json; charset=utf-8)

        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "title": "Arbitrary Code Execution",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.flex.blazeds:blazeds](https://github.com/apache/flex-blazeds) is an application development framework for easily building Flash-based applications for mobile devices, web browsers, and desktops.\n\n\nAffected versions of this package are vulnerable to Arbitrary Code Execution.\nThe AMF deserialization implementation of Flex BlazeDS is vulnerable to Deserialization of Untrusted Data. By sending a specially crafted AMF message, it is possible to make the server establish a connection to an endpoint specified in the message and request an RMI remote object from that endpoint. This can result in the execution of arbitrary code on the server via Java deserialization.\r\n\r\nStarting with BlazeDS version `4.7.3`, Deserialization of XML is disabled completely per default, while the `ClassDeserializationValidator` allows deserialization of whitelisted classes only. BlazeDS internally comes with the following whitelist:\r\n```\r\nflex.messaging.io.amf.ASObject\r\nflex.messaging.io.amf.SerializedObject\r\nflex.messaging.io.ArrayCollection\r\nflex.messaging.io.ArrayList\r\nflex.messaging.messages.AcknowledgeMessage\r\nflex.messaging.messages.AcknowledgeMessageExt\r\nflex.messaging.messages.AsyncMessage\r\nflex.messaging.messages.AsyncMessageExt\r\nflex.messaging.messages.CommandMessage\r\nflex.messaging.messages.CommandMessageExt\r\nflex.messaging.messages.ErrorMessage\r\nflex.messaging.messages.HTTPMessage\r\nflex.messaging.messages.RemotingMessage\r\nflex.messaging.messages.SOAPMessage\r\njava.lang.Boolean\r\njava.lang.Byte\r\njava.lang.Character\r\njava.lang.Double\r\njava.lang.Float\r\njava.lang.Integer\r\njava.lang.Long\r\njava.lang.Object\r\njava.lang.Short\r\njava.lang.String\r\njava.util.ArrayList\r\njava.util.Date\r\njava.util.HashMap\r\norg.w3c.dom.Document\r\n```\n\n## Remediation\n\nUpgrade `org.apache.flex.blazeds:blazeds` to version 4.7.3 or higher.\n\n\n## References\n\n- [CVE-2017-3066](https://nvd.nist.gov/vuln/detail/CVE-2017-5641)\n\n- [Github Commit](https://github.com/apache/flex-blazeds/commit/f861f0993c35e664906609cad275e45a71e2aaf1)\n\n- [Github Release Notes](https://github.com/apache/flex-blazeds/blob/master/RELEASE_NOTES)\n\n- [Securitytracker Issue](http://www.securitytracker.com/id/1038364)\n",
                  "functions": [],
                  "from": [
                    "org.apache.flex.blazeds:blazeds@4.7.2"
                  ],
                  "package": "org.apache.flex.blazeds:blazeds",
                  "version": "4.7.2",
                  "severity": "critical",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[,4.7.3)"
                    ]
                  },
                  "publicationTime": "2017-08-09T14:17:08Z",
                  "disclosureTime": "2017-04-25T21:00:00Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2017-5641"
                    ],
                    "CWE": [
                      "CWE-502"
                    ]
                  },
                  "credit": [
                    "Markus Wulftange"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvssScore": 9.8,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.flex.blazeds:blazeds@4.7.3"
                  ]
                }
              ],
              "licenses": []
            },
            "dependencyCount": 1,
            "org": {
              "name": "atokeneduser",
              "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
            },
            "licensesPolicy": null,
            "packageManager": "maven"
        }



### Test gradle file [POST /test/gradle{?org,repository}]
You can test your Gradle packages for issues according to their manifest file using this action. It takes a JSON object containing the "target" `build.gradle`.


+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (Gradle request payload)


+ Response 200 (application/json; charset=utf-8)


        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-JAVA-AXIS-30071",
                "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30071",
                "title": "Man-in-the-Middle (MitM)",
                "type": "vuln",
                "description": "## Overview\n\n[axis:axis](https://search.maven.org/search?q=g:axis) is an implementation of the SOAP (\"Simple Object Access Protocol\") submission to W3C.\n\n\nAffected versions of this package are vulnerable to Man-in-the-Middle (MitM).\nIt does not verify the requesting server's hostname against existing domain names in the SSL Certificate. \r\n\r\n## Details\r\nThe `getCN` function in Apache Axis 1.4 and earlier does not properly verify that the server hostname matches a domain name in the subject's `Common Name (CN)` or `subjectAltName` field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via a certificate with a subject that specifies a common name in a field that is not the CN field.  \r\n\r\n**NOTE:** this issue exists because of an incomplete fix for [CVE-2012-5784](https://snyk.io/vuln/SNYK-JAVA-AXIS-30189).\n\n## Remediation\n\nThere is no fixed version for `axis:axis`.\n\n\n## References\n\n- [Axis Issue](https://issues.apache.org/jira/browse/AXIS-2905)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3596)\n\n- [Redhat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-3596)\n",
                "functions": [],
                "from": [
                  "axis:axis@1.4"
                ],
                "package": "axis:axis",
                "version": "1.4",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[0,]"
                  ]
                },
                "publicationTime": "2014-08-18T16:51:53Z",
                "disclosureTime": "2014-08-18T16:51:53Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-3596"
                  ],
                  "CWE": [
                    "CWE-297"
                  ]
                },
                "credit": [
                  "David Jorm",
                  "Arun Neelicattu"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cvssScore": 5.4,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-JAVA-AXIS-30189",
                "url": "https://snyk.io/vuln/SNYK-JAVA-AXIS-30189",
                "title": "Man-in-the-Middle (MitM)",
                "type": "vuln",
                "description": "## Overview\n\n[axis:axis](https://search.maven.org/search?q=g:axis) is an implementation of the SOAP (\"Simple Object Access Protocol\") submission to W3C.\n\n\nAffected versions of this package are vulnerable to Man-in-the-Middle (MitM).\nIt does not verify the requesting server's hostname against existing domain names in the SSL Certificate.\r\n\r\n## Details\r\nApache Axis 1.4 and earlier does not properly verify that the server hostname matches a domain name in the subject's `Common Name (CN)` or `subjectAltName` field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.\n\n## Remediation\n\nThere is no fixed version for `axis:axis`.\n\n\n## References\n\n- [Jira Issue](https://issues.apache.org/jira/browse/AXIS-2883)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-5784)\n\n- [Texas University](http://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)\n",
                "functions": [],
                "from": [
                  "axis:axis@1.4"
                ],
                "package": "axis:axis",
                "version": "1.4",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[0,]"
                  ]
                },
                "publicationTime": "2017-03-13T08:00:21Z",
                "disclosureTime": "2012-11-04T22:55:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2012-5784"
                  ],
                  "CWE": [
                    "CWE-20"
                  ]
                },
                "credit": [
                  "Alberto Fernández"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cvssScore": 5.4,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 6,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "gradle"
        }



## sbt [/test/sbt{?org,repository}]
Test for issues in sbt files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.

### Test for issues in a public package by group id, artifact id and version  [GET /test/sbt/{groupId}/{artifactId}/{version}{?org,repository}]
You can test `sbt` packages for issues according to their group ID, artifact ID and version. This is done via the maven endpoint (for Java), since the packages are hosted on maven central or a compatible repository. See "Maven" above for details.

+ Parameters
    + groupId: `org.apache.flex.blazeds` (string, required) - The package's group ID.
    + artifactId: `blazeds` (string, required) - The package's artifact ID.
    + version: `4.7.2` (string, required) - The package version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.
    + repository: `https://repo1.maven.org/maven2` (string, optional) - The repository hosting this package. The default value is Maven Central. More than one value is supported, in order.


+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
            "ok": false,
            "issues": {
              "vulnerabilities": [
                {
                  "id": "SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEFLEXBLAZEDS-31455",
                  "title": "Arbitrary Code Execution",
                  "type": "vuln",
                  "description": "## Overview\n\n[org.apache.flex.blazeds:blazeds](https://github.com/apache/flex-blazeds) is an application development framework for easily building Flash-based applications for mobile devices, web browsers, and desktops.\n\n\nAffected versions of this package are vulnerable to Arbitrary Code Execution.\nThe AMF deserialization implementation of Flex BlazeDS is vulnerable to Deserialization of Untrusted Data. By sending a specially crafted AMF message, it is possible to make the server establish a connection to an endpoint specified in the message and request an RMI remote object from that endpoint. This can result in the execution of arbitrary code on the server via Java deserialization.\r\n\r\nStarting with BlazeDS version `4.7.3`, Deserialization of XML is disabled completely per default, while the `ClassDeserializationValidator` allows deserialization of whitelisted classes only. BlazeDS internally comes with the following whitelist:\r\n```\r\nflex.messaging.io.amf.ASObject\r\nflex.messaging.io.amf.SerializedObject\r\nflex.messaging.io.ArrayCollection\r\nflex.messaging.io.ArrayList\r\nflex.messaging.messages.AcknowledgeMessage\r\nflex.messaging.messages.AcknowledgeMessageExt\r\nflex.messaging.messages.AsyncMessage\r\nflex.messaging.messages.AsyncMessageExt\r\nflex.messaging.messages.CommandMessage\r\nflex.messaging.messages.CommandMessageExt\r\nflex.messaging.messages.ErrorMessage\r\nflex.messaging.messages.HTTPMessage\r\nflex.messaging.messages.RemotingMessage\r\nflex.messaging.messages.SOAPMessage\r\njava.lang.Boolean\r\njava.lang.Byte\r\njava.lang.Character\r\njava.lang.Double\r\njava.lang.Float\r\njava.lang.Integer\r\njava.lang.Long\r\njava.lang.Object\r\njava.lang.Short\r\njava.lang.String\r\njava.util.ArrayList\r\njava.util.Date\r\njava.util.HashMap\r\norg.w3c.dom.Document\r\n```\n\n## Remediation\n\nUpgrade `org.apache.flex.blazeds:blazeds` to version 4.7.3 or higher.\n\n\n## References\n\n- [CVE-2017-3066](https://nvd.nist.gov/vuln/detail/CVE-2017-5641)\n\n- [Github Commit](https://github.com/apache/flex-blazeds/commit/f861f0993c35e664906609cad275e45a71e2aaf1)\n\n- [Github Release Notes](https://github.com/apache/flex-blazeds/blob/master/RELEASE_NOTES)\n\n- [Securitytracker Issue](http://www.securitytracker.com/id/1038364)\n",
                  "functions": [],
                  "from": [
                    "org.apache.flex.blazeds:blazeds@4.7.2"
                  ],
                  "package": "org.apache.flex.blazeds:blazeds",
                  "version": "4.7.2",
                  "severity": "critical",
                  "exploitMaturity": "no-known-exploit",
                  "language": "java",
                  "packageManager": "maven",
                  "semver": {
                    "vulnerable": [
                      "[,4.7.3)"
                    ]
                  },
                  "publicationTime": "2017-08-09T14:17:08Z",
                  "disclosureTime": "2017-04-25T21:00:00Z",
                  "isUpgradable": true,
                  "isPatchable": false,
                  "isPinnable": false,
                  "identifiers": {
                    "CVE": [
                      "CVE-2017-5641"
                    ],
                    "CWE": [
                      "CWE-502"
                    ]
                  },
                  "credit": [
                    "Markus Wulftange"
                  ],
                  "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvssScore": 9.8,
                  "patches": [],
                  "upgradePath": [
                    "org.apache.flex.blazeds:blazeds@4.7.3"
                  ]
                }
              ],
              "licenses": []
            },
            "dependencyCount": 1,
            "org": {
              "name": "atokeneduser",
              "id": "689ce7f9-7943-4a71-b704-2ba575f01089"
            },
            "licensesPolicy": null,
            "packageManager": "maven"
        }



### Test sbt file [POST /test/sbt{?org,repository}]
You can test your `sbt` packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `build.sbt`.

+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (sbt request payload)


+ Response 200 (application/json; charset=utf-8)


        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-JAVA-COMNING-30317",
                "url": "https://snyk.io/vuln/SNYK-JAVA-COMNING-30317",
                "title": "Insufficient Verification of Data Authenticity",
                "type": "vuln",
                "description": "## Overview\n[`com.ning:async-http-client`](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22async-http-client%22)\nAsync Http Client (aka AHC or async-http-client) before 1.9.0 skips X.509 certificate verification unless both a keyStore location and a trustStore location are explicitly set, which allows man-in-the-middle attackers to spoof HTTPS servers by presenting an arbitrary certificate during use of a typical AHC configuration, as demonstrated by a configuration that does not send client certificates.\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-7397)\n- [OSS Security](http://openwall.com/lists/oss-security/2014/08/26/1)\n- [GitHub Issue](https://github.com/AsyncHttpClient/async-http-client/issues/352)\n- [GitHub Commit](https://github.com/AsyncHttpClient/async-http-client/commit/dfacb8e05d0822c7b2024c452554bd8e1d6221d8)\n",
                "functions": [],
                "from": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.2",
                  "com.ning:async-http-client@1.8.10"
                ],
                "package": "com.ning:async-http-client",
                "version": "1.8.10",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,1.9.0)"
                  ]
                },
                "publicationTime": "2017-03-28T08:29:28.375000Z",
                "disclosureTime": "2015-06-24T16:59:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-7397"
                  ],
                  "CWE": [
                    "CWE-345"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "cvssScore": 4.3,
                "patches": [],
                "upgradePath": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.3",
                  "com.ning:async-http-client@1.9.11"
                ]
              },
              {
                "id": "SNYK-JAVA-COMNING-30318",
                "url": "https://snyk.io/vuln/SNYK-JAVA-COMNING-30318",
                "title": "Insufficient Verification of Data Authenticity",
                "type": "vuln",
                "description": "## Overview\n[`com.ning:async-http-client`](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22async-http-client%22)\nmain/java/com/ning/http/client/AsyncHttpClientConfig.java in Async Http Client (aka AHC or async-http-client) before 1.9.0 does not require a hostname match during verification of X.509 certificates, which allows man-in-the-middle attackers to spoof HTTPS servers via an arbitrary valid certificate.\n\n## References\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-7398)\n- [GitHub Commit](https://github.com/AsyncHttpClient/async-http-client/issues/197)\n- [GitHub Commit](https://github.com/AsyncHttpClient/async-http-client/commit/dfacb8e05d0822c7b2024c452554bd8e1d6221d8)\n- [OSS Security](http://openwall.com/lists/oss-security/2014/08/26/1)\n",
                "functions": [],
                "from": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.2",
                  "com.ning:async-http-client@1.8.10"
                ],
                "package": "com.ning:async-http-client",
                "version": "1.8.10",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,1.9.0)"
                  ]
                },
                "publicationTime": "2017-03-28T08:29:28.445000Z",
                "disclosureTime": "2015-06-24T16:59:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-7398"
                  ],
                  "CWE": [
                    "CWE-345"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "cvssScore": 4.3,
                "patches": [],
                "upgradePath": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.3",
                  "com.ning:async-http-client@1.9.11"
                ]
              },
              {
                "id": "SNYK-JAVA-IONETTY-30430",
                "url": "https://snyk.io/vuln/SNYK-JAVA-IONETTY-30430",
                "title": "Information Disclosure",
                "type": "vuln",
                "description": "## Overview\n\n[io.netty:netty](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22netty%22) is a NIO client server framework which enables quick and easy development of network applications such as protocol servers and clients.\n\n\nAffected versions of this package are vulnerable to Information Disclosure.\nIt does not validate cookie name and value characters, allowing attackers to potentially bypass the `httpOnly` flag on sensitive cookies.\n\n## Remediation\n\nUpgrade `io.netty:netty` to version 3.9.8.Final, 3.10.3.Final or higher.\n\n\n## References\n\n- [GitHub Commit 3.10.3](https://github.com/netty/netty/commit/2caa38a2795fe1f1ae6ceda4d69e826ed7c55e55)\n\n- [GitHub Commit 3.9.8](https://github.com/netty/netty/commit/31815598a2af37f0b71ea94eada70d6659c23752)\n\n- [GitHub Commit 4.0.8](https://github.com/netty/netty/pull/3748/commits/4ac519f534493bb0ca7a77e1c779138a54faa7b9)\n\n- [GitHub PR 3.9.8 and 3.10.3](https://github.com/netty/netty/pull/3754)\n\n- [GitHub PR 4.0.28](https://github.com/netty/netty/pull/3748)\n\n- [Linkedin Security Blog](https://engineering.linkedin.com/security/look-netty_s-recent-security-update-cve--2015--2156)\n\n- [Release Notes 3.9.8 and 3.10.3](http://netty.io/news/2015/05/08/3-9-8-Final-and-3.html)\n\n- [Release Notes 4.0.28](http://netty.io/news/2015/05/07/4-0-28-Final.html)\n",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.jboss.netty.handler.codec.http.CookieEncoder",
                      "functionName": "encode"
                    },
                    "version": [
                      "[3.10.0,3.10.2)",
                      "[3.3.0,3.9.7)"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.jboss.netty.handler.codec.http.cookie.ServerCookieEncoder",
                      "functionName": "encode"
                    },
                    "version": [
                      "[3.9.7,3.9.8.Final)",
                      "[3.10.2,3.10.3.Final)"
                    ]
                  }
                ],
                "from": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.2",
                  "com.ning:async-http-client@1.8.10",
                  "io.netty:netty@3.9.2.Final"
                ],
                "package": "io.netty:netty",
                "version": "3.9.2.Final",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[3.3.0.Final,3.9.8.Final)",
                    "[3.10.0.Final,3.10.3.Final)"
                  ]
                },
                "publicationTime": "2015-04-08T21:44:31Z",
                "disclosureTime": "2015-04-08T21:44:31Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-2156"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Roman Shafigullin",
                  "Luca Carettoni",
                  "Mukul Khullar"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.4",
                  "com.ning:async-http-client@1.9.40",
                  "io.netty:netty@3.10.6.Final"
                ]
              },
              {
                "id": "SNYK-JAVA-IONETTY-473694",
                "url": "https://snyk.io/vuln/SNYK-JAVA-IONETTY-473694",
                "title": "HTTP Request Smuggling",
                "type": "vuln",
                "description": "## Overview\n\n[io.netty:netty](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22netty%22) is a NIO client server framework which enables quick and easy development of network applications such as protocol servers and clients.\n\n\nAffected versions of this package are vulnerable to HTTP Request Smuggling.\nNetty mishandles whitespace before the colon in HTTP headers such as a `Transfer-Encoding : chunked` line. This can lead to HTTP request smuggling where an attacker can bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.\n\n## Remediation\n\nThere is no fixed version for `io.netty:netty`.\n\n\n## References\n\n- [GitHub Fix Commit](https://github.com/netty/netty/commit/017a9658c97ff1a1355c31a6a1f8bd1ea6f21c8d)\n\n- [GitHub Issue](https://github.com/netty/netty/issues/9571)\n\n- [GitHub PR](https://github.com/netty/netty/pull/9585)\n",
                "functions": [],
                "from": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.2",
                  "com.ning:async-http-client@1.8.10",
                  "io.netty:netty@3.9.2.Final"
                ],
                "package": "io.netty:netty",
                "version": "3.9.2.Final",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[0,]"
                  ]
                },
                "publicationTime": "2019-09-26T17:08:57Z",
                "disclosureTime": "2019-09-26T17:08:57Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-16869"
                  ],
                  "CWE": [
                    "CWE-113"
                  ]
                },
                "credit": [
                  "axeBig"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/E:U/RL:O/RC:R",
                "cvssScore": 6.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-JAVA-NETSOURCEFORGEHTMLUNIT-548471",
                "url": "https://snyk.io/vuln/SNYK-JAVA-NETSOURCEFORGEHTMLUNIT-548471",
                "title": "Remote Code Execution (RCE)",
                "type": "vuln",
                "description": "## Overview\n\n[net.sourceforge.htmlunit:htmlunit](http://htmlunit.sourceforge.net) is a GUI-Less browser for Java programs\n\n\nAffected versions of this package are vulnerable to Remote Code Execution (RCE).\nIt initializes Rhino engine improperly, hence a malicious JavaScript code can execute arbitrary Java code on the application.\n\n## Remediation\n\nUpgrade `net.sourceforge.htmlunit:htmlunit` to version 2.37.0 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/HtmlUnit/htmlunit/commit/bc1f58d483cc8854a9c4c1739abd5e04a2eb0367)\n\n- [JvNDB](https://jvn.jp/en/jp/JVN34535327/)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20"
                ],
                "package": "net.sourceforge.htmlunit:htmlunit",
                "version": "2.20",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,2.37.0)"
                  ]
                },
                "publicationTime": "2020-02-11T09:35:13Z",
                "disclosureTime": "2020-02-10T09:35:13Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2020-5529"
                  ],
                  "CWE": [
                    "CWE-284",
                    "CWE-94"
                  ]
                },
                "credit": [
                  "ICHIHARA Ryohei"
                ],
                "CVSSv3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/E:U/RL:O/RC:R",
                "cvssScore": 5.6,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-31517",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-31517",
                "title": "Directory Traversal",
                "type": "vuln",
                "description": "## Overview\n\n[org.apache.httpcomponents:httpclient](http://hc.apache.org/) is a HttpClient component of the Apache HttpComponents project.\n\n\nAffected versions of this package are vulnerable to Directory Traversal.\nString input by user is not validated for the presence of leading character `/` and is passed to the constructor as `path` information, resulting in a Directory Traversal vulnerability.\n\n## Details\nA Directory Traversal attack (also known as path traversal) aims to access files and directories that are stored outside the intended folder. By manipulating files with \"dot-dot-slash (../)\" sequences and its variations, or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system, including application source code, configuration, and other critical system files.\r\n\r\nDirectory Traversal vulnerabilities can be generally divided into two types:\r\n\r\n- **Information Disclosure**: Allows the attacker to gain information about the folder structure or read the contents of sensitive files on the system.\r\n\r\n`st` is a module for serving static files on web pages, and contains a [vulnerability of this type](https://snyk.io/vuln/npm:st:20140206). In our example, we will serve files from the `public` route.\r\n\r\nIf an attacker requests the following URL from our server, it will in turn leak the sensitive private key of the root user.\r\n\r\n```\r\ncurl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa\r\n```\r\n**Note** `%2e` is the URL encoded version of `.` (dot).\r\n\r\n- **Writing arbitrary files**: Allows the attacker to create or replace existing files. This type of vulnerability is also known as `Zip-Slip`. \r\n\r\nOne way to achieve this is by using a malicious `zip` archive that holds path traversal filenames. When each filename in the zip archive gets concatenated to the target extraction folder, without validation, the final path ends up outside of the target folder. If an executable or a configuration file is overwritten with a file containing malicious code, the problem can turn into an arbitrary code execution issue quite easily.\r\n\r\nThe following is an example of a `zip` archive with one benign file and one malicious file. Extracting the malicious file will result in traversing out of the target folder, ending up in `/root/.ssh/` overwriting the `authorized_keys` file:\r\n\r\n```\r\n2018-04-15 22:04:29 .....           19           19  good.txt\r\n2018-04-15 22:04:42 .....           20           20  ../../../../../../root/.ssh/authorized_keys\r\n```\n\n\n## Remediation\n\nUpgrade `org.apache.httpcomponents:httpclient` to version 4.5.3 or higher.\n\n\n## References\n\n- [Github Commit](https://github.com/apache/httpcomponents-client/commit/0554271750599756d4946c0d7ba43d04b1a7b220)\n\n- [Jira Issue](https://issues.apache.org/jira/browse/HTTPCLIENT-1803)\n\n- [Researcher blog post](http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html)\n",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.apache.http.client.utils.URIUtils",
                      "functionName": "normalizePath"
                    },
                    "version": [
                      "[4.1,4.1.3]"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.apache.http.client.utils.URIBuilder",
                      "functionName": "normalizePath"
                    },
                    "version": [
                      "[4.2.1 ,4.5.2)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.apache.httpcomponents:httpclient@4.5.2"
                ],
                "package": "org.apache.httpcomponents:httpclient",
                "version": "4.5.2",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,4.5.3)"
                  ]
                },
                "publicationTime": "2017-09-20T00:00:00Z",
                "disclosureTime": "2017-01-17T00:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-23"
                  ]
                },
                "credit": [
                  "James Kettle"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-31517",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGAPACHEHTTPCOMPONENTS-31517",
                "title": "Directory Traversal",
                "type": "vuln",
                "description": "## Overview\n\n[org.apache.httpcomponents:httpclient](http://hc.apache.org/) is a HttpClient component of the Apache HttpComponents project.\n\n\nAffected versions of this package are vulnerable to Directory Traversal.\nString input by user is not validated for the presence of leading character `/` and is passed to the constructor as `path` information, resulting in a Directory Traversal vulnerability.\n\n## Details\nA Directory Traversal attack (also known as path traversal) aims to access files and directories that are stored outside the intended folder. By manipulating files with \"dot-dot-slash (../)\" sequences and its variations, or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system, including application source code, configuration, and other critical system files.\r\n\r\nDirectory Traversal vulnerabilities can be generally divided into two types:\r\n\r\n- **Information Disclosure**: Allows the attacker to gain information about the folder structure or read the contents of sensitive files on the system.\r\n\r\n`st` is a module for serving static files on web pages, and contains a [vulnerability of this type](https://snyk.io/vuln/npm:st:20140206). In our example, we will serve files from the `public` route.\r\n\r\nIf an attacker requests the following URL from our server, it will in turn leak the sensitive private key of the root user.\r\n\r\n```\r\ncurl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa\r\n```\r\n**Note** `%2e` is the URL encoded version of `.` (dot).\r\n\r\n- **Writing arbitrary files**: Allows the attacker to create or replace existing files. This type of vulnerability is also known as `Zip-Slip`. \r\n\r\nOne way to achieve this is by using a malicious `zip` archive that holds path traversal filenames. When each filename in the zip archive gets concatenated to the target extraction folder, without validation, the final path ends up outside of the target folder. If an executable or a configuration file is overwritten with a file containing malicious code, the problem can turn into an arbitrary code execution issue quite easily.\r\n\r\nThe following is an example of a `zip` archive with one benign file and one malicious file. Extracting the malicious file will result in traversing out of the target folder, ending up in `/root/.ssh/` overwriting the `authorized_keys` file:\r\n\r\n```\r\n2018-04-15 22:04:29 .....           19           19  good.txt\r\n2018-04-15 22:04:42 .....           20           20  ../../../../../../root/.ssh/authorized_keys\r\n```\n\n\n## Remediation\n\nUpgrade `org.apache.httpcomponents:httpclient` to version 4.5.3 or higher.\n\n\n## References\n\n- [Github Commit](https://github.com/apache/httpcomponents-client/commit/0554271750599756d4946c0d7ba43d04b1a7b220)\n\n- [Jira Issue](https://issues.apache.org/jira/browse/HTTPCLIENT-1803)\n\n- [Researcher blog post](http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html)\n",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.apache.http.client.utils.URIUtils",
                      "functionName": "normalizePath"
                    },
                    "version": [
                      "[4.1,4.1.3]"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.apache.http.client.utils.URIBuilder",
                      "functionName": "normalizePath"
                    },
                    "version": [
                      "[4.2.1 ,4.5.2)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.apache.httpcomponents:httpmime@4.5.2",
                  "org.apache.httpcomponents:httpclient@4.5.2"
                ],
                "package": "org.apache.httpcomponents:httpclient",
                "version": "4.5.2",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,4.5.3)"
                  ]
                },
                "publicationTime": "2017-09-20T00:00:00Z",
                "disclosureTime": "2017-01-17T00:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-23"
                  ]
                },
                "credit": [
                  "James Kettle"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26",
                  "org.apache.httpcomponents:httpmime@4.5.3",
                  "org.apache.httpcomponents:httpclient@4.5.3"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[org.eclipse.jetty:jetty-util](https://www.eclipse.org/jetty) is a Web Container & Clients - supports HTTP/2, HTTP/1.1, HTTP/1.0, websocket, servlets, and more.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nwhen a remote client uses a specially formatted URL against the `DefaultServlet` or `ResourceHandler` that is configured for showing a listing of directory contents.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `org.eclipse.jetty:jetty-util` to version 9.2.27.v20190403, 9.3.26.v20190403, 9.4.16.v20190411 or higher.\n\n\n## References\n\n- [Eclipse Report](https://bugs.eclipse.org/bugs/show_bug.cgi?id=546121)\n\n- [GitHub Commit](https://github.com/eclipse/jetty.project/commit/ca77bd384a2970cabbbdab25cf6251c6fb76cd21)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "medium",
                "exploitMaturity": "mature",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[9.2.0.M0,9.2.27.v20190403)",
                    "[9.3.0.M0, 9.3.26.v20190403)",
                    "[9.4.15.v20190215, 9.4.16.v20190411)"
                  ]
                },
                "publicationTime": "2019-04-22T21:08:57Z",
                "disclosureTime": "2019-04-22T21:08:57Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-10241"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/E:F",
                "cvssScore": 4.7,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-util@9.4.3.v20170317"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[org.eclipse.jetty:jetty-util](https://www.eclipse.org/jetty) is a Web Container & Clients - supports HTTP/2, HTTP/1.1, HTTP/1.0, websocket, servlets, and more.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nwhen a remote client uses a specially formatted URL against the `DefaultServlet` or `ResourceHandler` that is configured for showing a listing of directory contents.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `org.eclipse.jetty:jetty-util` to version 9.2.27.v20190403, 9.3.26.v20190403, 9.4.16.v20190411 or higher.\n\n\n## References\n\n- [Eclipse Report](https://bugs.eclipse.org/bugs/show_bug.cgi?id=546121)\n\n- [GitHub Commit](https://github.com/eclipse/jetty.project/commit/ca77bd384a2970cabbbdab25cf6251c6fb76cd21)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-io@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "medium",
                "exploitMaturity": "mature",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[9.2.0.M0,9.2.27.v20190403)",
                    "[9.3.0.M0, 9.3.26.v20190403)",
                    "[9.4.15.v20190215, 9.4.16.v20190411)"
                  ]
                },
                "publicationTime": "2019-04-22T21:08:57Z",
                "disclosureTime": "2019-04-22T21:08:57Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-10241"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/E:F",
                "cvssScore": 4.7,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-io@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-util@9.4.3.v20170317"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[org.eclipse.jetty:jetty-util](https://www.eclipse.org/jetty) is a Web Container & Clients - supports HTTP/2, HTTP/1.1, HTTP/1.0, websocket, servlets, and more.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nwhen a remote client uses a specially formatted URL against the `DefaultServlet` or `ResourceHandler` that is configured for showing a listing of directory contents.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `org.eclipse.jetty:jetty-util` to version 9.2.27.v20190403, 9.3.26.v20190403, 9.4.16.v20190411 or higher.\n\n\n## References\n\n- [Eclipse Report](https://bugs.eclipse.org/bugs/show_bug.cgi?id=546121)\n\n- [GitHub Commit](https://github.com/eclipse/jetty.project/commit/ca77bd384a2970cabbbdab25cf6251c6fb76cd21)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty.websocket:websocket-common@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "medium",
                "exploitMaturity": "mature",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[9.2.0.M0,9.2.27.v20190403)",
                    "[9.3.0.M0, 9.3.26.v20190403)",
                    "[9.4.15.v20190215, 9.4.16.v20190411)"
                  ]
                },
                "publicationTime": "2019-04-22T21:08:57Z",
                "disclosureTime": "2019-04-22T21:08:57Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-10241"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/E:F",
                "cvssScore": 4.7,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.3.v20170317",
                  "org.eclipse.jetty.websocket:websocket-common@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-util@9.4.3.v20170317"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-174479",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[org.eclipse.jetty:jetty-util](https://www.eclipse.org/jetty) is a Web Container & Clients - supports HTTP/2, HTTP/1.1, HTTP/1.0, websocket, servlets, and more.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nwhen a remote client uses a specially formatted URL against the `DefaultServlet` or `ResourceHandler` that is configured for showing a listing of directory contents.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `org.eclipse.jetty:jetty-util` to version 9.2.27.v20190403, 9.3.26.v20190403, 9.4.16.v20190411 or higher.\n\n\n## References\n\n- [Eclipse Report](https://bugs.eclipse.org/bugs/show_bug.cgi?id=546121)\n\n- [GitHub Commit](https://github.com/eclipse/jetty.project/commit/ca77bd384a2970cabbbdab25cf6251c6fb76cd21)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty.websocket:websocket-common@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-io@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "medium",
                "exploitMaturity": "mature",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[9.2.0.M0,9.2.27.v20190403)",
                    "[9.3.0.M0, 9.3.26.v20190403)",
                    "[9.4.15.v20190215, 9.4.16.v20190411)"
                  ]
                },
                "publicationTime": "2019-04-22T21:08:57Z",
                "disclosureTime": "2019-04-22T21:08:57Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-10241"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N/E:F",
                "cvssScore": 4.7,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.2.1",
                  "net.sourceforge.htmlunit:htmlunit@2.26",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.3.v20170317",
                  "org.eclipse.jetty.websocket:websocket-common@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-io@9.4.3.v20170317",
                  "org.eclipse.jetty:jetty-util@9.4.3.v20170317"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\r\n[org.eclipse.jetty:jetty-util](https://github.com/eclipse/jetty.project)  is a lightweight highly scalable java based web server and servlet engine.\r\n\r\nAffected versions of this package are vulnerable to Timing Attacks. A flaw in the `util/security/Password.java` class makes it easier for remote attackers to obtain access by observing elapsed times before rejection of incorrect passwords.\r\n\r\n## Remediation\r\nUpgrade `org.eclipse.jetty:jetty-util` to versions 9.2.22, 9.3.20, 9.4.6 or higher.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-9735)\r\n- [GitHub Issue](https://github.com/eclipse/jetty.project/issues/1556)",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Credential",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Password",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,9.2.22.v20170606)",
                    "[9.3.0.M0, 9.3.20.v20170531)",
                    "[9.4.0.M0, 9.4.6.v20170531)"
                  ]
                },
                "publicationTime": "2018-04-03T08:07:27Z",
                "disclosureTime": "2017-06-16T21:29:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-9735"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@2.1.0",
                  "net.sourceforge.htmlunit:htmlunit@2.29",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-util@9.4.8.v20171121"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\r\n[org.eclipse.jetty:jetty-util](https://github.com/eclipse/jetty.project)  is a lightweight highly scalable java based web server and servlet engine.\r\n\r\nAffected versions of this package are vulnerable to Timing Attacks. A flaw in the `util/security/Password.java` class makes it easier for remote attackers to obtain access by observing elapsed times before rejection of incorrect passwords.\r\n\r\n## Remediation\r\nUpgrade `org.eclipse.jetty:jetty-util` to versions 9.2.22, 9.3.20, 9.4.6 or higher.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-9735)\r\n- [GitHub Issue](https://github.com/eclipse/jetty.project/issues/1556)",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Credential",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Password",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-io@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,9.2.22.v20170606)",
                    "[9.3.0.M0, 9.3.20.v20170531)",
                    "[9.4.0.M0, 9.4.6.v20170531)"
                  ]
                },
                "publicationTime": "2018-04-03T08:07:27Z",
                "disclosureTime": "2017-06-16T21:29:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-9735"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@2.1.0",
                  "net.sourceforge.htmlunit:htmlunit@2.29",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-io@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-util@9.4.8.v20171121"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\r\n[org.eclipse.jetty:jetty-util](https://github.com/eclipse/jetty.project)  is a lightweight highly scalable java based web server and servlet engine.\r\n\r\nAffected versions of this package are vulnerable to Timing Attacks. A flaw in the `util/security/Password.java` class makes it easier for remote attackers to obtain access by observing elapsed times before rejection of incorrect passwords.\r\n\r\n## Remediation\r\nUpgrade `org.eclipse.jetty:jetty-util` to versions 9.2.22, 9.3.20, 9.4.6 or higher.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-9735)\r\n- [GitHub Issue](https://github.com/eclipse/jetty.project/issues/1556)",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Credential",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Password",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty.websocket:websocket-common@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,9.2.22.v20170606)",
                    "[9.3.0.M0, 9.3.20.v20170531)",
                    "[9.4.0.M0, 9.4.6.v20170531)"
                  ]
                },
                "publicationTime": "2018-04-03T08:07:27Z",
                "disclosureTime": "2017-06-16T21:29:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-9735"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@2.1.0",
                  "net.sourceforge.htmlunit:htmlunit@2.29",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.8.v20171121",
                  "org.eclipse.jetty.websocket:websocket-common@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-util@9.4.8.v20171121"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-32151",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\r\n[org.eclipse.jetty:jetty-util](https://github.com/eclipse/jetty.project)  is a lightweight highly scalable java based web server and servlet engine.\r\n\r\nAffected versions of this package are vulnerable to Timing Attacks. A flaw in the `util/security/Password.java` class makes it easier for remote attackers to obtain access by observing elapsed times before rejection of incorrect passwords.\r\n\r\n## Remediation\r\nUpgrade `org.eclipse.jetty:jetty-util` to versions 9.2.22, 9.3.20, 9.4.6 or higher.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-9735)\r\n- [GitHub Issue](https://github.com/eclipse/jetty.project/issues/1556)",
                "functions": [
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Credential",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  },
                  {
                    "functionId": {
                      "className": "org.eclipse.jetty.util.security.Password",
                      "functionName": "check"
                    },
                    "version": [
                      "(8.0.4.v20111024 ,9.2.22.v20170606)",
                      "[9.3.0, 9.3.20.v20170531)",
                      "[9.4.0, 9.4.6.v20170531)"
                    ]
                  }
                ],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "org.eclipse.jetty.websocket:websocket-client@9.2.15.v20160210",
                  "org.eclipse.jetty.websocket:websocket-common@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-io@9.2.15.v20160210",
                  "org.eclipse.jetty:jetty-util@9.2.15.v20160210"
                ],
                "package": "org.eclipse.jetty:jetty-util",
                "version": "9.2.15.v20160210",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,9.2.22.v20170606)",
                    "[9.3.0.M0, 9.3.20.v20170531)",
                    "[9.4.0.M0, 9.4.6.v20170531)"
                  ]
                },
                "publicationTime": "2018-04-03T08:07:27Z",
                "disclosureTime": "2017-06-16T21:29:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-9735"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@2.1.0",
                  "net.sourceforge.htmlunit:htmlunit@2.29",
                  "org.eclipse.jetty.websocket:websocket-client@9.4.8.v20171121",
                  "org.eclipse.jetty.websocket:websocket-common@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-io@9.4.8.v20171121",
                  "org.eclipse.jetty:jetty-util@9.4.8.v20171121"
                ]
              },
              {
                "id": "SNYK-JAVA-ORGSCALALANG-31592",
                "url": "https://snyk.io/vuln/SNYK-JAVA-ORGSCALALANG-31592",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`org.scala-lang:scala-compiler`](https://scala-lang.org) are vulnerable to Arbitrary Code Execution.\n\nThe compilation daemon in Scala before 2.10.7, 2.11.x before 2.11.12, and 2.12.x before 2.12.4 uses weak permissions for private files in /tmp/scala-devel/${USER:shared}/scalac-compile-server-port, which allows local users to write to arbitrary class files and consequently gain privileges.\n\n## Remediation\nUpgrade `org.scala-lang:scala-compiler` to version 2.12.4 or higher.\n\n## References\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-15288)\n- [GitHub PR #1](https://github.com/scala/scala/pull/6108)\n- [GitHub PR #2](https://github.com/scala/scala/pull/6120)\n- [GitHub PR #3](https://github.com/scala/scala/pull/6128)\n- [GitHub Commit #1](https://github.com/scala/scala/commit/f3419fc358a8ea6e366538126279da88d4d1fb1f)\n- [GitHub Commit #2](https://github.com/scala/scala/commit/67fcf5ce4496000574676d81ed72e4a6cb9e7757)\n- [GitHub Commit #3](https://github.com/scala/scala/commit/0f624c5e5bdb39967e208c7c16067c3e6c903f1f)\n",
                "functions": [],
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "org.scala-lang:scala-compiler@2.11.8"
                ],
                "package": "org.scala-lang:scala-compiler",
                "version": "2.11.8",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[,2.10.7),[2.11,2.11.12),[2.12,2.12.4)"
                  ]
                },
                "publicationTime": "2017-11-28T14:47:22.036000Z",
                "disclosureTime": "2017-10-02T21:00:00Z",
                "isUpgradable": true,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-15288"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 7.8,
                "patches": [],
                "upgradePath": [
                  "net.ruippeixotog:scala-scraper_2.11@1.1.0"
                ]
              }
            ],
            "licenses": [
              {
                "id": "snyk:lic:maven:net.databinder.dispatch:dispatch-core_2.11:LGPL-3.0",
                "url": "https://snyk.io/vuln/snyk:lic:maven:net.databinder.dispatch:dispatch-core_2.11:LGPL-3.0",
                "title": "LGPL-3.0 license",
                "type": "license",
                "from": [
                  "net.databinder.dispatch:dispatch-core_2.11@0.11.2"
                ],
                "package": "net.databinder.dispatch:dispatch-core_2.11",
                "version": "0.11.2",
                "severity": "medium",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[0,)"
                  ]
                }
              },
              {
                "id": "snyk:lic:maven:net.sourceforge.cssparser:cssparser:LGPL-2.0",
                "url": "https://snyk.io/vuln/snyk:lic:maven:net.sourceforge.cssparser:cssparser:LGPL-2.0",
                "title": "LGPL-2.0 license",
                "type": "license",
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "net.sourceforge.cssparser:cssparser@0.9.18"
                ],
                "package": "net.sourceforge.cssparser:cssparser",
                "version": "0.9.18",
                "severity": "medium",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[0.9.6, 0.9.19)"
                  ]
                }
              },
              {
                "id": "snyk:lic:maven:net.sourceforge.htmlunit:htmlunit-core-js:MPL-2.0",
                "url": "https://snyk.io/vuln/snyk:lic:maven:net.sourceforge.htmlunit:htmlunit-core-js:MPL-2.0",
                "title": "MPL-2.0 license",
                "type": "license",
                "from": [
                  "net.ruippeixotog:scala-scraper_2.11@1.0.0",
                  "net.sourceforge.htmlunit:htmlunit@2.20",
                  "net.sourceforge.htmlunit:htmlunit-core-js@2.17"
                ],
                "package": "net.sourceforge.htmlunit:htmlunit-core-js",
                "version": "2.17",
                "severity": "medium",
                "language": "java",
                "packageManager": "maven",
                "semver": {
                  "vulnerable": [
                    "[2.11,)"
                  ]
                }
              }
            ]
          },
          "dependencyCount": 44,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "sbt"
        }


## pip [/test/pip{?org}]
Test for issues in pip files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

### Test for issues in a public package by name and version  [GET /test/pip/{packageName}/{version}{?org}]
You can test `pip` packages for issues according to their name and version.

+ Parameters
    + packageName: `rsa` (string, required) - The package name.
    + version: `3.3` (string, required) - The Package version to test.
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.


+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY



+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-PYTHON-RSA-40541",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-RSA-40541",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\n[`rsa`](https://pypi.python.org/pypi/rsa) is a Pure-Python RSA implementation.\n\nAffected versions of this package are vulnerable to Timing attacks.\n\n## References\n- [GitHub Issue](https://github.com/sybrenstuvel/python-rsa/issues/19)\n- [GitHub Commit](https://github.com/sybrenstuvel/python-rsa/commit/2310b34bdb530e0bad793d42f589c9f848ff181b)\n",
                "functions": [],
                "from": [
                  "rsa@3.3"
                ],
                "package": "rsa",
                "version": "3.3",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": [
                    "[3.0,3.4.0)"
                  ]
                },
                "publicationTime": "2013-11-15T02:34:45.265000Z",
                "disclosureTime": "2013-11-15T02:34:45.265000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": true,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-208"
                  ]
                },
                "credit": [
                  "Manuel Aude Morales"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-RSA-40542",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-RSA-40542",
                "title": "Authentication Bypass",
                "type": "vuln",
                "description": "## Overview\n[`rsa`](https://pypi.python.org/pypi/rsa) is a Pure-Python RSA implementation.\n\nAffected versions of this package are vulnerable to Authentication Bypass due to not implementing authentication encryption or use MACs to validate messages before decrypting public key encrypted messages.\n\n## References\n- [GitHub Issue](https://github.com/sybrenstuvel/python-rsa/issues/13)\n- [GitHub Commit](https://github.com/sybrenstuvel/python-rsa/commit/1681a0b2f84a4a252c71b87de870a2816de06fdf)\n",
                "functions": [],
                "from": [
                  "rsa@3.3"
                ],
                "package": "rsa",
                "version": "3.3",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": [
                    "[3.0,3.4)"
                  ]
                },
                "publicationTime": "2012-12-07T03:15:00.052000Z",
                "disclosureTime": "2012-12-07T03:15:00.052000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": true,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-287"
                  ]
                },
                "credit": [
                  "Sergio Lerner"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 2,
          "org": {
            "name": "gitphill",
            "id": "229b76f3-802c-4553-aa1d-01d4d86f7f61"
          },
          "licensesPolicy": null,
          "packageManager": "pip"
        }



### Test requirements.txt file [POST /test/pip{?org}]
You can test your pip packages for issues according to their manifest file using this action. It takes a JSON object containing a the "target" `requirements.txt`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (pip request payload)


+ Response 200 (application/json; charset=utf-8)


        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-PYTHON-OAUTH2-40013",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-OAUTH2-40013",
                "title": "Replay Attack",
                "type": "vuln",
                "description": "## Overview\r\n[`oauth2`](https://pypi.python.org/pypi/oauth2) is a library for OAuth version 1.9\r\nThe Server.verify_request function in SimpleGeo python-oauth2 does not check the nonce, which allows remote attackers to perform replay attacks via a signed URL.\r\n\r\n## Remediation\r\nUpgrade to version `1.9rc1` or greater.\r\n\r\n## References\r\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2013-4346)\r\n- [Bugzilla redhat](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4346)\r\n- [GitHub Issue](https://github.com/simplegeo/python-oauth2/issues/129)\r\n",
                "functions": [],
                "from": [
                  "oauth2@1.5.211"
                ],
                "package": "oauth2",
                "version": "1.5.211",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": [
                    "[,1.9rc1)"
                  ]
                },
                "publicationTime": "2013-02-05T12:31:58Z",
                "disclosureTime": "2013-02-05T12:31:58Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": true,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-4346"
                  ],
                  "CWE": [
                    "CWE-310"
                  ]
                },
                "credit": [
                  "André Cruz"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                "cvssScore": 4.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-OAUTH2-40014",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-OAUTH2-40014",
                "title": "Insecure Randomness",
                "type": "vuln",
                "description": "## Overview\r\n[`oauth2`](https://pypi.python.org/pypi/oauth2) is a library for OAuth version 1.9\r\n\r\nAffected versions of this package are vulnerable to Insecure Randomness.\r\nThe (1) make_nonce, (2) generate_nonce, and (3) generate_verifier functions in SimpleGeo python-oauth2 uses weak random numbers to generate nonces, which makes it easier for remote attackers to guess the nonce via a brute force attack.\r\n\r\n## Remediation\r\nUpgrade to version `1.9rc1` or greater.\r\n\r\n## References\r\n- [Redhat Bugzilla](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2013-4347)\r\n- [GitHub Issue](https://github.com/simplegeo/python-oauth2/issues/9)\r\n- [Openwall](http://www.openwall.com/lists/oss-security/2013/09/12/7)\r\n- [GitHub PR](https://github.com/simplegeo/python-oauth2/pull/146)\r\n",
                "functions": [],
                "from": [
                  "oauth2@1.5.211"
                ],
                "package": "oauth2",
                "version": "1.5.211",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": [
                    "[,1.9rc1)"
                  ]
                },
                "publicationTime": "2017-04-13T12:31:58Z",
                "disclosureTime": "2014-05-20T14:55:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": true,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-4347"
                  ],
                  "CWE": [
                    "CWE-310"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cvssScore": 5.4,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PYTHON-SUPERVISOR-40610",
                "url": "https://snyk.io/vuln/SNYK-PYTHON-SUPERVISOR-40610",
                "title": "Arbitrary Command Execution",
                "type": "vuln",
                "description": "## Overview\r\n[`supervisor`](https://pypi.python.org/pypi/supervisor/) is a client/server system that allows its users to monitor and control a number of processes on UNIX-like operating systems.\r\n\r\nAffected versions of the package are vulnerable to Arbitrary Command Execution. A vulnerability has been found where an authenticated client can send a malicious XML-RPC request to `supervisord` that will run arbitrary shell commands on the server. The commands will be run as the same user as `supervisord`. Depending on how `supervisord` has been configured, this may be root.\r\n\r\n## Details\r\n* `supervisord` is the server component and is responsible for starting child processes, responding to commands from clients, and other commands.\r\n* `supervisorctl` is the command line component, providing a shell-like interface to the features provided by `supervisord`.\r\n\r\n`supervisord` can be configured to run an HTTP server on a TCP socket and/or a Unix domain socket. This HTTP server is how `supervisorctl` communicates with `supervisord`. If an HTTP server has been enabled, it will always serve both HTML pages and an XML-RPC interface. A vulnerability has been found where an authenticated client can send a malicious XML-RPC request to `supervisord` that will run arbitrary shell commands on the server. The commands will be run as the same user as `supervisord`. Depending on how `supervisord` has been configured, this may be root.\r\nThis vulnerability can only be exploited by an authenticated client or if `supervisord` has been configured to run an HTTP server without authentication. If authentication has not been enabled, `supervisord` will log a message at the critical level every time it starts.\r\n\r\n## PoC by Maor Shwartz\r\n\r\nCreate a config file `supervisord.conf`:\r\n\r\n```conf\r\n[supervisord]\r\nloglevel = trace\r\n\r\n[inet_http_server]\r\nport = 127.0.0.1:9001\r\n\r\n[rpcinterface:supervisor]\r\nsupervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface\r\n```\r\n\r\nStart supervisord in the foreground with that config file:\r\n\r\n```\r\n$ supervisord -n -c supervisord.conf\r\n```\r\n\r\nIn a new terminal:\r\n\r\n```py\r\n$ python2\r\n>>> from xmlrpclib import ServerProxy\r\n>>> server = ServerProxy('http://127.0.0.1:9001/RPC2')\r\n>>> server.supervisor.supervisord.options.execve('/bin/sh', [], {})\r\n  ```\r\n\r\nIf the `supervisord` version is vulnerable, the `execve` will be executed and the `supervisord` process will be replaced with /bin/sh (or any other command given). If the `supervisord` version is not vulnerable, it will return an `UNKNOWN_METHOD` fault.\r\n\r\n\r\n## Remediation\r\nUpgrade `supervisor` to version 3.3.3 or higher.\r\n\r\n## References\r\n- [Github Issue](https://github.com/Supervisor/supervisor/issues/964)\r\n- [Github Commit 3.0.1](https://github.com/Supervisor/supervisor/commit/83060f3383ebd26add094398174f1de34cf7b7f0)\r\n- [Github Commit 3.1.4](https://github.com/Supervisor/supervisor/commit/dbe0f55871a122eac75760aef511efc3a8830b88)\r\n- [Github Commit 3.2.4](https://github.com/Supervisor/supervisor/commit/aac3c21893cab7361f5c35c8e20341b298f6462e)\r\n- [Github Commit 3.3.3](https://github.com/Supervisor/supervisor/commit/058f46141e346b18dee0497ba11203cb81ecb19e)",
                "functions": [],
                "from": [
                  "supervisor@3.1.0"
                ],
                "package": "supervisor",
                "version": "3.1.0",
                "severity": "high",
                "exploitMaturity": "mature",
                "language": "python",
                "packageManager": "pip",
                "semver": {
                  "vulnerable": [
                    "[3.0a1,3.0.1)",
                    "[3.1.0,3.1.4)",
                    "[3.2.0,3.2.4)",
                    "[3.3.0,3.3.3)"
                  ]
                },
                "publicationTime": "2017-08-08T06:59:14Z",
                "disclosureTime": "2017-07-18T21:00:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": true,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-11610"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Maor Shwartz"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C",
                "cvssScore": 8.8,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 4,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "pip"
        }

## composer [/test/composer{?org}]
Test for issues in PHP composer.json and composer.lock files.

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.



### Test composer.json & composer.lock file [POST /test/composer{?org}]
You can test your Composer packages for issues according to their manifest file & lockfile using this action. It takes a JSON object containing a "target" `composer.json` and a `composer.lock`.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Test Packages`

    + Headers

            Authorization: token API_KEY

    + Attributes (composer request payload)


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "issues": {
            "vulnerabilities": [
              {
                "id": "SNYK-PHP-AWSAWSSDKPHP-70003",
                "url": "https://snyk.io/vuln/SNYK-PHP-AWSAWSSDKPHP-70003",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\n  Affected versions of [`aws/aws-sdk-php`](https://packagist.org/packages/aws/aws-sdk-php) are vulnerable to Arbitrary Code Execution.\n\nDoctrine Annotations before 1.2.7, Cache before 1.3.2 and 1.4.x before 1.4.2, Common before 2.4.3 and 2.5.x before 2.5.1, ORM before 2.4.8 or 2.5.x before 2.5.1, MongoDB ODM before 1.0.2, and MongoDB ODM Bundle before 3.0.1 use world-writable permissions for cache directories, which allows local users to execute arbitrary PHP code with additional privileges by leveraging an application with the umask set to 0 and that executes cache entries as code.\n\n## Remediation\nUpgrade `aws/aws-sdk-php` to version 3.2.1 or higher.\n\n## References\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-5723)\n- [Github ChangeLog](https://github.com/aws/aws-sdk-php/blob/master/CHANGELOG.md#321---2015-07-23)\n",
                "functions": [],
                "from": [
                  "aws/aws-sdk-php@3.0.0"
                ],
                "package": "aws/aws-sdk-php",
                "version": "3.0.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<3.2.1"
                  ]
                },
                "publicationTime": "2015-07-24T00:41:41Z",
                "disclosureTime": "2015-07-24T00:41:41Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-5723"
                  ],
                  "CWE": [
                    "CWE-264"
                  ]
                },
                "credit": [
                  "Ryan Lane"
                ],
                "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 7.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-DOCTRINECOMMON-70024",
                "url": "https://snyk.io/vuln/SNYK-PHP-DOCTRINECOMMON-70024",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`doctrine/common`](https://packagist.org/packages/doctrine/common) are vulnerable to Arbitrary Code Execution.\n\nDoctrine Annotations before 1.2.7, Cache before 1.3.2 and 1.4.x before 1.4.2, Common before 2.4.3 and 2.5.x before 2.5.1, ORM before 2.4.8 or 2.5.x before 2.5.1, MongoDB ODM before 1.0.2, and MongoDB ODM Bundle before 3.0.1 use world-writable permissions for cache directories, which allows local users to execute arbitrary PHP code with additional privileges by leveraging an application with the umask set to 0 and that executes cache entries as code.\n\n## Remediation\nUpgrade `doctrine/common` to version 2.5.1, 2.4.3 or higher.\n\n## References\n- [Doctrine Release Notes](http://www.doctrine-project.org/2015/08/31/security_misconfiguration_vulnerability_in_various_doctrine_projects.html)\n",
                "functions": [],
                "from": [
                  "doctrine/common@2.5.0"
                ],
                "package": "doctrine/common",
                "version": "2.5.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.3",
                    ">=2.5.0, <2.5.1"
                  ]
                },
                "publicationTime": "2015-08-31T14:42:59Z",
                "disclosureTime": "2015-08-31T14:42:59Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-5723"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Ryan Lane"
                ],
                "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 7.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-DOCTRINECOMMON-70024",
                "url": "https://snyk.io/vuln/SNYK-PHP-DOCTRINECOMMON-70024",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`doctrine/common`](https://packagist.org/packages/doctrine/common) are vulnerable to Arbitrary Code Execution.\n\nDoctrine Annotations before 1.2.7, Cache before 1.3.2 and 1.4.x before 1.4.2, Common before 2.4.3 and 2.5.x before 2.5.1, ORM before 2.4.8 or 2.5.x before 2.5.1, MongoDB ODM before 1.0.2, and MongoDB ODM Bundle before 3.0.1 use world-writable permissions for cache directories, which allows local users to execute arbitrary PHP code with additional privileges by leveraging an application with the umask set to 0 and that executes cache entries as code.\n\n## Remediation\nUpgrade `doctrine/common` to version 2.5.1, 2.4.3 or higher.\n\n## References\n- [Doctrine Release Notes](http://www.doctrine-project.org/2015/08/31/security_misconfiguration_vulnerability_in_various_doctrine_projects.html)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1",
                  "doctrine/common@2.5.0"
                ],
                "package": "doctrine/common",
                "version": "2.5.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.3",
                    ">=2.5.0, <2.5.1"
                  ]
                },
                "publicationTime": "2015-08-31T14:42:59Z",
                "disclosureTime": "2015-08-31T14:42:59Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-5723"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Ryan Lane"
                ],
                "CVSSv3": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 7.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-173743",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-173743",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a PHP framework for web applications and a set of reusable PHP components.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS).\nA remote attacker could inject arbitrary web script or HTML via the \"file\" parameter in a URL.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `symfony/symfony` to version 4.1 or higher.\n\n\n## References\n\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12040)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<4.1"
                  ]
                },
                "publicationTime": "2018-06-14T00:35:49Z",
                "disclosureTime": "2018-06-08T00:35:49Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-12040"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-173744",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-173744",
                "title": "Host Header Injection",
                "type": "vuln",
                "description": "## Overview\n\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a PHP framework for web applications and a set of reusable PHP components.\n\n\nAffected versions of this package are vulnerable to Host Header Injection.\nWhen using `HttpCache`, the values of the `X-Forwarded-Host` headers are implicitly set as trusted while this should be forbidden, leading to potential host header injection.\n\n## Remediation\n\nUpgrade `symfony/symfony` to version 2.7.49, 2.8.44, 3.3.18, 3.4.14, 4.0.14, 4.1.2 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/symfony/symfony/commit/725dee4cd8b4ccd52e335ae4b4522242cea9bd4a)\n\n- [GitHub Release Tag 4.1.3](https://github.com/symfony/symfony/releases/tag/v4.1.3)\n\n- [Symphony Security Blog](https://symfony.com/blog/cve-2018-14774-possible-host-header-injection-when-using-httpcache)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.49",
                    ">=2.8.0, <2.8.44",
                    ">=3.3.0, <3.3.18",
                    ">=3.4.0, <3.4.14",
                    ">=4.0.0, <4.0.14",
                    ">=4.1.0, <4.1.2"
                  ]
                },
                "publicationTime": "2018-08-05T13:44:27Z",
                "disclosureTime": "2018-07-31T17:24:43Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-14774"
                  ],
                  "CWE": [
                    "CWE-444"
                  ]
                },
                "credit": [
                  "Chaosversum"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
                "cvssScore": 7.2,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-173745",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-173745",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a PHP framework for web applications and a set of reusable PHP components.\n\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS)\nvia the content page.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\n\nUpgrade `symfony/symfony` to version 2.7.7 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/symphonycms/symphony-2/commit/1ace6b31867cc83267b3550686271c9c65ac3ec0)\n\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2018-12043)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.7"
                  ]
                },
                "publicationTime": "2018-06-13T10:56:51Z",
                "disclosureTime": "2018-06-07T21:05:47Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-12043"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70207",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70207",
                "title": "Loss of Information",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Loss of Information.\n\nWhen using the Validator component, if Symfony\\\\Component\\\\Validator\\\\Mapping\\\\Cache\\\\ApcCache is enabled (or any other cache implementing Symfony\\\\Component\\\\Validator\\\\Mapping\\\\Cache\\\\CacheInterface), some information is lost during serialization (the collectionCascaded and the collectionCascadedDeeply fields).\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.3, 2.1.12, 2.2.5, 2.0.24 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/security-releases-symfony-2-0-24-2-1-12-2-2-5-and-2-3-3-released)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "low",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.3",
                    ">=2.1.0, <2.1.12",
                    ">=2.2.0, <2.2.5",
                    ">=2, <2.0.24"
                  ]
                },
                "publicationTime": "2013-08-17T07:55:32Z",
                "disclosureTime": "2013-08-17T07:55:32Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-4751"
                  ],
                  "CWE": [
                    "CWE-221"
                  ]
                },
                "credit": [
                  "Alexandre Salome"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 3.7,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70208",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70208",
                "title": "HTTP Host Header Poisoning",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to HTTP Host Header Poisoning.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.3, 2.1.12, 2.2.5, 2.0.24 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/security-releases-symfony-2-0-24-2-1-12-2-2-5-and-2-3-3-released)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.3",
                    ">=2.1.0, <2.1.12",
                    ">=2.2.0, <2.2.5",
                    ">=2, <2.0.24"
                  ]
                },
                "publicationTime": "2013-08-17T09:14:49Z",
                "disclosureTime": "2013-08-17T09:14:49Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-4752"
                  ],
                  "CWE": [
                    "CWE-74"
                  ]
                },
                "credit": [
                  "Jordan Alliot"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "cvssScore": 8.2,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70209",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70209",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Denial of Service (DoS).\n\nThe Security component in Symfony 2.0.x before 2.0.25, 2.1.x before 2.1.13, 2.2.x before 2.2.9, and 2.3.x before 2.3.6 allows remote attackers to cause a denial of service (CPU consumption) via a long password that triggers an expensive hash computation, as demonstrated by a PBKDF2 computation, a similar issue to [CVE-2013-5750](https://snyk.io/vuln/SNYK-PHP-FRIENDSOFSYMFONYUSERBUNDLE-70102).\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.6, 2.1.13, 2.2.9, 2.0.25 or higher.\n\n## References\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2013-5958)\n- [Symfony Release Notes](http://symfony.com/blog/security-releases-cve-2013-5958-symfony-2-0-25-2-1-13-2-2-9-and-2-3-6-released)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2, <2.0.25",
                    ">=2.1.0, <2.1.13",
                    ">=2.2.0, <2.2.9",
                    ">=2.3.0, <2.3.6"
                  ]
                },
                "publicationTime": "2013-10-10T08:30:51Z",
                "disclosureTime": "2013-10-10T08:30:51Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2013-5958"
                  ],
                  "CWE": [
                    "CWE-400"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70210",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70210",
                "title": "Arbitrary Code Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Arbitrary Code Injection.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.19, 2.2.0, 2.4.9, 2.5.4, 2.3.0, 2.1.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/security-releases-cve-2014-4931-symfony-2-3-18-2-4-8-and-2-5-2-released)\n- [GitHub Commit](https://github.com/symfony/symfony/commit/06a80fbdbe744ad6f3010479ba64ef5cf35dd9af)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.19",
                    ">=2.1.0, <2.2.0",
                    ">=2.4.0, <2.4.9",
                    ">=2.5.0, <2.5.4",
                    ">=2.2.0, <2.3.0",
                    ">=2, <2.1.0"
                  ]
                },
                "publicationTime": "2014-07-25T22:18:02Z",
                "disclosureTime": "2014-07-25T22:18:02Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-4931"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Jeremy Derussé"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 5.6,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70211",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70211",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Denial of Service (DoS).\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.19, 2.4.9, 2.5.4 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2014-5244-denial-of-service-with-a-malicious-http-host-header)\n- [GitHub PR](https://github.com/symfony/symfony/pull/11828)\n- [GitHub Commit](https://github.com/symfony/symfony/commit/1ee96a8b1b0987ffe2a62dca7ad268bf9edfa9b8)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2, <2.3.19",
                    ">=2.4.0, <2.4.9",
                    ">=2.5.0, <2.5.4"
                  ]
                },
                "publicationTime": "2014-09-03T07:37:21Z",
                "disclosureTime": "2014-09-03T07:37:21Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-5244"
                  ],
                  "CWE": [
                    "CWE-400"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70212",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70212",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Information Exposure.\n\nWhen you enable the ESI feature and when you are using a proxy like Varnish that you configured as a trusted proxy, the FragmentHandler considered requests to render fragments as coming from a trusted source, even if the client was requesting them directly. Symfony can not distinguish between ESI requests done on behalf of the client by Varnish and faked fragment requests coming directly from the client.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.19, 2.2.0, 2.4.9, 2.5.4, 2.3.0, 2.1.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2014-5245-direct-access-of-esi-urls-behind-a-trusted-proxy)\n- [GitHub PR](https://github.com/symfony/symfony/pull/11831)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "low",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.19",
                    ">=2.1.0, <2.2.0",
                    ">=2.4.0, <2.4.9",
                    ">=2.5.0, <2.5.4",
                    ">=2.2.0, <2.3.0",
                    ">=2, <2.1.0"
                  ]
                },
                "publicationTime": "2014-09-03T07:40:02Z",
                "disclosureTime": "2014-09-03T07:40:02Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-5245"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Cédric Nirousset",
                  "Trent Steel",
                  "Christophe Coevoet"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 3.7,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70213",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70213",
                "title": "Authentication Bypass",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Authentication Bypass.\n\nWhen an application uses an HTTP basic or digest authentication, Symfony does not parse the Authorization header properly, which could be exploited in some server setups (no exploits have been demonstrated though.)\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.19, 2.2.0, 2.4.9, 2.5.4, 2.3.0, 2.1.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2014-6061-security-issue-when-parsing-the-authorization-header)\n- [GitHub Issue](https://github.com/symfony/symfony/pull/11829)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "low",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.19",
                    ">=2.1.0, <2.2.0",
                    ">=2.4.0, <2.4.9",
                    ">=2.5.0, <2.5.4",
                    ">=2.2.0, <2.3.0",
                    ">=2, <2.1.0"
                  ]
                },
                "publicationTime": "2014-09-03T07:38:23Z",
                "disclosureTime": "2014-09-03T07:38:23Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-6061"
                  ],
                  "CWE": [
                    "CWE-592"
                  ]
                },
                "credit": [
                  "Damien Tournoud"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 3.7,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70214",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70214",
                "title": "Cross-site Request Forgery (CSRF)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Cross-site Request Forgery (CSRF).\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.19, 2.2.0, 2.4.9, 2.5.4, 2.3.0, 2.1.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2014-6072-csrf-vulnerability-in-the-web-profiler)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.19",
                    ">=2.1.0, <2.2.0",
                    ">=2.4.0, <2.4.9",
                    ">=2.5.0, <2.5.4",
                    ">=2.2.0, <2.3.0",
                    ">=2, <2.1.0"
                  ]
                },
                "publicationTime": "2014-09-03T07:40:30Z",
                "disclosureTime": "2014-09-03T07:40:30Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-6072"
                  ],
                  "CWE": [
                    "CWE-352"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70215",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70215",
                "title": "Arbitrary Code Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Arbitrary Code Injection.\n\nEval injection vulnerability in the HttpCache class in HttpKernel in Symfony 2.x before 2.3.27, 2.4.x and 2.5.x before 2.5.11, and 2.6.x before 2.6.6 allows remote attackers to execute arbitrary PHP code via a `language=\"php\"` attribute of a SCRIPT element.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.27, 2.6.6, 2.2.0, 2.5.0, 2.5.11, 2.3.0, 2.1.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2015-2308-esi-code-injection)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.27",
                    ">=2.6.0, <2.6.6",
                    ">=2.1.0, <2.2.0",
                    ">=2.4.0, <2.5.0",
                    ">=2.5.0, <2.5.11",
                    ">=2.2.0, <2.3.0",
                    ">=2, <2.1.0"
                  ]
                },
                "publicationTime": "2015-04-01T18:55:26Z",
                "disclosureTime": "2015-04-01T18:55:26Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-2308"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70216",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70216",
                "title": "Man-in-the-Middle (MitM)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Man-in-the-Middle (MitM).\n\nThe `Symfony\\Component\\HttpFoundation\\Request` class provides a mechanism that ensures it does not trust HTTP header values coming from a \"non-trusted\" client. Unfortunately, it assumes that the remote address is always a trusted client if at least one trusted proxy is involved in the request; this allows a man-in-the-middle attack between the latest trusted proxy and the web server.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.27, 2.5.11, 2.6.6 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2015-2309-unsafe-methods-in-the-request-class)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2, <2.3.27",
                    ">=2.4.0, <2.5.11",
                    ">=2.6.0, <2.6.6"
                  ]
                },
                "publicationTime": "2015-04-01T18:55:26Z",
                "disclosureTime": "2015-04-01T18:55:26Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-2309"
                  ],
                  "CWE": [
                    "CWE-300"
                  ]
                },
                "credit": [
                  "Dmitrii Chekaliuk"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "cvssScore": 6.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70218",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70218",
                "title": "Session Fixation",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Session Fixation.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.35, 2.6.12, 2.5.0, 2.7.7, 2.6.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2015-8124-session-fixation-in-the-remember-me-login-feature)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.35",
                    ">=2.6.0, <2.6.12",
                    ">=2.4.0, <2.5.0",
                    ">=2.7.0, <2.7.7",
                    ">=2.5.0, <2.6.0"
                  ]
                },
                "publicationTime": "2015-11-23T11:45:06Z",
                "disclosureTime": "2015-11-23T11:45:06Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-8124"
                  ],
                  "CWE": [
                    "CWE-384"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70219",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70219",
                "title": "Timing Attack",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Timing Attack.\n\nSymfony 2.3.x before 2.3.35, 2.6.x before 2.6.12, and 2.7.x before 2.7.7 might allow remote attackers to have unspecified impact via a timing attack involving:\n* Symfony/Component/Security/Http/RememberMe/PersistentTokenBasedRememberMeServices or\n* Symfony/Component/Security/Http/Firewall/DigestAuthenticationListener class in the Symfony Security Component, or\n* legacy CSRF implementation from the Symfony/Component/Form/Extension/Csrf/CsrfProvider/DefaultCsrfProvider class in the Symfony Form component.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.35, 2.6.12, 2.5.0, 2.7.7, 2.6.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2015-8125-potential-remote-timing-attack-vulnerability-in-security-remember-me-service)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.35",
                    ">=2.6.0, <2.6.12",
                    ">=2.4.0, <2.5.0",
                    ">=2.7.0, <2.7.7",
                    ">=2.5.0, <2.6.0"
                  ]
                },
                "publicationTime": "2015-11-23T11:45:06Z",
                "disclosureTime": "2015-11-23T11:45:06Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-8125"
                  ],
                  "CWE": [
                    "CWE-208"
                  ]
                },
                "credit": [
                  "Sebastiaan Stok"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70220",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70220",
                "title": "Insecure Randomness",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Insecure Randomness .\n\nThe nextBytes function in the SecureRandom class in Symfony before 2.3.37, 2.6.x before 2.6.13, and 2.7.x before 2.7.9 does not properly generate random numbers when used with PHP 5.x without the paragonie/random_compat library and the openssl_random_pseudo_bytes function fails, which makes it easier for attackers to defeat cryptographic protection mechanisms via unspecified vectors.\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.37, 2.6.13, 2.5.0, 2.7.9, 2.6.0 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2016-1902-securerandom-s-fallback-not-secure-when-openssl-fails)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.37",
                    ">=2.6.0, <2.6.13",
                    ">=2.4.0, <2.5.0",
                    ">=2.7.0, <2.7.9",
                    ">=2.5.0, <2.6.0"
                  ]
                },
                "publicationTime": "2016-01-14T09:59:32Z",
                "disclosureTime": "2016-01-14T09:59:32Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2016-1902"
                  ],
                  "CWE": [
                    "CWE-330"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-70222",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70222",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`symfony/symfony`](https://packagist.org/packages/symfony/symfony) are vulnerable to Denial of Service (DoS).\n\nThe attemptAuthentication function in Component/Security/Http/Firewall/UsernamePasswordFormAuthenticationListener.php in Symfony before 2.3.41, 2.7.x before 2.7.13, 2.8.x before 2.8.6, and 3.0.x before 3.0.6 does not limit the length of a username stored in a session, which allows remote attackers to cause a denial of service (session storage consumption) via a series of authentication attempts with long, non-existent usernames.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\nUpgrade `symfony/symfony` to version 2.3.41, 2.7.0, 2.5.0, 2.7.13, 2.6.0, 2.8.6, 3.0.6 or higher.\n\n## References\n- [Symfony Release Notes](http://symfony.com/blog/cve-2016-4423-large-username-storage-in-session)\n- [GitHub PR](https://github.com/symfony/symfony/pull/18733)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.41",
                    ">=2.6.0, <2.7.0",
                    ">=2.4.0, <2.5.0",
                    ">=2.7.0, <2.7.13",
                    ">=2.5.0, <2.6.0",
                    ">=2.8.0, <2.8.6",
                    ">=3, <3.0.6"
                  ]
                },
                "publicationTime": "2016-05-09T21:31:02Z",
                "disclosureTime": "2016-05-09T21:31:02Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2016-4423"
                  ],
                  "CWE": [
                    "CWE-400"
                  ]
                },
                "credit": [
                  "Marek Alaksa"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72196",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72196",
                "title": "Denial of Service (DoS)",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a set of reusable PHP components.\n\nAffected versions of this package are vulnerable to Denial of Service (DoS) attacks via the `PDOSessionHandler` class.\n\n**An application is vulnerable when:**\n\n* It uses `PDOSessionHandler` to store its sessions\n* And it uses MySQL as a backend for sessions managed by `PDOSessionHandler`\n* And the SQL mode does not contain `STRICT_ALL_TABLES` or `STRICT_TRANS_TABLES`.\n\nWith this configuration, An attacker may conduct a denial of service by a well-crafted session, which leads to an infinite loop in the code.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its intended and legitimate users.\r\n\r\nUnlike other vulnerabilities, DoS attacks usually do not aim at breaching security. Rather, they are focused on making websites and services unavailable to genuine users resulting in downtime.\r\n\r\nOne popular Denial of Service vulnerability is DDoS (a Distributed Denial of Service), an attack that attempts to clog network pipes to the system by generating a large volume of traffic from many machines.\r\n\r\nWhen it comes to open source libraries, DoS vulnerabilities allow attackers to trigger such a crash or crippling of the service by using a flaw either in the application code or from the use of open source libraries.\r\n\r\nTwo common types of DoS vulnerabilities:\r\n\r\n* High CPU/Memory Consumption- An attacker sending crafted requests that could cause the system to take a disproportionate amount of time to process. For example, [commons-fileupload:commons-fileupload](SNYK-JAVA-COMMONSFILEUPLOAD-30082).\r\n\r\n* Crash - An attacker sending crafted requests that could cause the system to crash. For Example,  [npm `ws` package](npm:ws:20171108)\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.7.48, 2.8.41, 3.3.17, 3.4.11, 4.0.11 or higher.\n\n## References\n- [Symphony Security Advisory](https://symfony.com/cve-2018-11386)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.48",
                    ">=2.8.0, <2.8.41",
                    ">=3.0.0, <3.3.17",
                    ">=3.4.0, <3.4.11",
                    ">=4.0.0, <4.0.11"
                  ]
                },
                "publicationTime": "2018-05-30T11:36:38.154000Z",
                "disclosureTime": "2018-05-30T03:25:45.531000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-11386"
                  ],
                  "CWE": [
                    "CWE-835"
                  ]
                },
                "credit": [
                  "Federico Stange"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "cvssScore": 5.9,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72197",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72197",
                "title": "Access Restriction Bypass",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a set of PHP components.\n\nAffected versions of this package are vulnerable to Access Restriction Bypass. A misconfigured LDAP server allowed unauthorized access, due to a missing check for `null` passwords.\n\n**Note:** This is related to [CVE-2016-2403](https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70221).\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.8.37, 3.3.17, 3.4.7, 4.0.7 or higher.\n\n## References\n- [Symphony Security Advisory](https://symfony.com/cve-2018-11407)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "critical",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.8.37",
                    ">=3.0.0, <3.3.17",
                    ">=3.4.0, <3.4.7",
                    ">=4.0.0, <4.0.7"
                  ]
                },
                "publicationTime": "2018-05-30T11:36:38.236000Z",
                "disclosureTime": "2018-05-30T03:25:45.532000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-11407"
                  ],
                  "CWE": [
                    "CWE-284"
                  ]
                },
                "credit": [
                  "Theo Bouge"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 9.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72198",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72198",
                "title": "CSRF Token Fixation",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a set of reusable PHP components.\n\nAffected versions of this package are vulnerable to CSRF Token Fixation. CSRF tokens where not erased during logout, when the `invalidate_session` option was disabled. By default, a user’s session is invalidated when the user is logged out.\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.7.48, 2.8.41, 3.3.17, 3.4.11, 4.0.11 or higher.\n\n## References\n- [Symphony Security Advisory](https://symfony.com/cve-2018-11406)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.48",
                    ">=2.8.0, <2.8.41",
                    ">=3.0.0, <3.3.17",
                    ">=3.4.0, <3.4.11",
                    ">=4.0.0, <4.0.11"
                  ]
                },
                "publicationTime": "2018-05-30T11:36:38.318000Z",
                "disclosureTime": "2018-05-30T03:25:45.533000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-11406"
                  ],
                  "CWE": [
                    "CWE-384"
                  ]
                },
                "credit": [
                  "Kevin Liagre"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "cvssScore": 8.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72199",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72199",
                "title": "Open Redirect",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a set of reusable PHP components.\n\nAffected versions of this package are vulnerable to Open Redirect. This is due to an incomplete fix for [CVE-2017-16652](https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-70381). There was an an edge case when the `security.http_utils` was inlined by the container.\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.7.48, 2.8.41, 3.3.17, 3.4.11, 4.0.11 or higher.\n\n## References\n- [Symphony Security Advisory](https://symfony.com/cve-2018-11408)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.48",
                    ">=2.8.0, <2.8.41",
                    ">=3.0.0, <3.3.17",
                    ">=3.4.0, <3.4.11",
                    ">=4.0.0, <4.0.11"
                  ]
                },
                "publicationTime": "2018-05-30T11:36:38.403000Z",
                "disclosureTime": "2018-05-30T03:25:45.535000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-11408"
                  ],
                  "CWE": [
                    "CWE-601"
                  ]
                },
                "credit": [
                  "Antal Aron"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72200",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72200",
                "title": "Session Fixation",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is a set of reusable PHP components.\n\nAffected versions of this package are vulnerable to Session Fixation via the `Guard` login feature. An attacker may be able to impersonate the victim towards the web application if the session id value was previously known to the attacker. This allows the attacker to access a Symfony web application with the attacked user's permissions.\n\n**Note:**\n* The `Guard authentication` login feature must be enabled for the attack to be applicable.\n* The attacker must have access to the `PHPSESSID` cookie value or has successfully set a new value in the user's browser.\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.7.48, 2.8.41, 3.3.17, 3.4.11, 4.0.11 or higher.\n\n## References\n- [Symphony Security Advisory](https://symfony.com/cve-2018-11385)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.48",
                    ">=2.8.0, <2.8.41",
                    ">=3.0.0, <3.3.17",
                    ">=3.4.0, <3.4.11",
                    ">=4.0.0, <4.0.11"
                  ]
                },
                "publicationTime": "2018-05-30T11:36:38.526000Z",
                "disclosureTime": "2018-05-30T03:25:45.536000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-11385"
                  ],
                  "CWE": [
                    "CWE-384"
                  ]
                },
                "credit": [
                  "Chris Wilkinson"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 8.1,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-SYMFONYSYMFONY-72246",
                "url": "https://snyk.io/vuln/SNYK-PHP-SYMFONYSYMFONY-72246",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\n[symfony/symfony](https://packagist.org/packages/symfony/symfony) is the The Symfony PHP framework.\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) attacks via the `ExceptionHandler.php` method.\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n\n## Remediation\nUpgrade `symfony/symfony` to versions 2.7.33, 2.8.26, 3.2.13, 3.3.6 or higher.\n\n## References\n- [GitHub PR](https://github.com/symfony/symfony/pull/23684)\n- [GitHub Issue](https://github.com/symfony/symfony/issues/27987)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1"
                ],
                "package": "symfony/symfony",
                "version": "2.3.1",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.7.33",
                    ">=2.8.0, <2.8.26",
                    ">=3.0.0, <3.2.13",
                    ">=3.3.0, <3.3.6"
                  ]
                },
                "publicationTime": "2018-07-30T13:57:42.005000Z",
                "disclosureTime": "2018-07-20T00:54:33.251000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2017-18343"
                  ],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cvssScore": 6.1,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-TWIGTWIG-173776",
                "url": "https://snyk.io/vuln/SNYK-PHP-TWIGTWIG-173776",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\n\n[twig/twig](https://packagist.org/packages/twig/twig) is a flexible, fast, and secure template language for PHP.\n\n\nAffected versions of this package are vulnerable to Information Exposure\ndue to allowing the evaluation of non-trusted templates in a sandbox, where everything is forbidden if not explicitly allowed by a sandbox policy (tags, filters, functions, method calls, ...).\r\n\r\n*Note: If you are not using the sandbox, your code is not affected.*\n\n## Remediation\n\nUpgrade `twig/twig` to version 1.38.0, 2.7.0 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/twigphp/Twig/commit/0f3af98ef6e71929ad67fb6e5f3ad65777c1c4c5)\n\n- [Twig Security Advisory](https://symfony.com/blog/twig-sandbox-information-disclosure)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1",
                  "twig/twig@1.35.0"
                ],
                "package": "twig/twig",
                "version": "1.35.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=1.0.0, <1.38.0",
                    ">=2.0.0, <2.7.0"
                  ]
                },
                "publicationTime": "2019-03-12T13:58:49Z",
                "disclosureTime": "2019-03-12T13:58:49Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2019-9942"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Fabien Potencier"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N/RL:O",
                "cvssScore": 4.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-TWIGTWIG-72239",
                "url": "https://snyk.io/vuln/SNYK-PHP-TWIGTWIG-72239",
                "title": "Server Side Template Injection (SSTI)",
                "type": "vuln",
                "description": "## Overview\n[twig/twig](https://packagist.org/packages/twig/twig) is a flexible, fast, and secure template language for PHP.\n\nAffected versions of this package are vulnerable to Server Side Template Injection (SSTI) via the `search_key` parameter.\n\n## Remediation\nUpgrade `twig/twig` to version 2.4.4 or higher.\n\n## References\n- [Exploit-DB](https://www.exploit-db.com/exploits/44102/)\n- [GitHub Commit](https://github.com/twigphp/Twig/commit/eddb97148ad779f27e670e1e3f19fb323aedafeb)\n- [GitHub ChangLog](https://github.com/twigphp/Twig/blob/2.x/CHANGELOG)\n",
                "functions": [],
                "from": [
                  "symfony/symfony@2.3.1",
                  "twig/twig@1.35.0"
                ],
                "package": "twig/twig",
                "version": "1.35.0",
                "severity": "critical",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.4"
                  ]
                },
                "publicationTime": "2018-07-23T13:46:08.115000Z",
                "disclosureTime": "2018-07-10T15:06:02.373000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2018-13818"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 9.8,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-YIISOFTYII-70295",
                "url": "https://snyk.io/vuln/SNYK-PHP-YIISOFTYII-70295",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`yiisoft/yii`](https://packagist.org/packages/yiisoft/yii) are vulnerable to Arbitrary Code Execution.\n\nThe CDetailView widget in Yii PHP Framework 1.1.14 allows remote attackers to execute arbitrary PHP scripts via vectors related to the value property.\n\n## Remediation\nUpgrade `yiisoft/yii` to version 1.1.15 or higher.\n\n## References\n- [Yii Framework Security Advisory](http://www.yiiframework.com/news/78/yii-1-1-15-is-released-security-fix/)\n",
                "functions": [],
                "from": [
                  "yiisoft/yii@1.1.14"
                ],
                "package": "yiisoft/yii",
                "version": "1.1.14",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<1.1.15"
                  ]
                },
                "publicationTime": "2014-06-30T07:15:00Z",
                "disclosureTime": "2014-06-30T07:15:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-4672"
                  ],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70321",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70321",
                "title": "Route Parameter Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Route Parameter Injection.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.1.4, 2.0.8 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2013-01)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.1.0, <2.1.4",
                    ">=2, <2.0.8"
                  ]
                },
                "publicationTime": "2013-03-13T08:39:38Z",
                "disclosureTime": "2013-03-13T08:39:38Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-74"
                  ]
                },
                "credit": [
                  "codemagician"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "cvssScore": 6.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70322",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70322",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Information Exposure.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.1.4, 2.0.8 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2013-02)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "low",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.1.0, <2.1.4",
                    ">=2, <2.0.8"
                  ]
                },
                "publicationTime": "2013-03-13T15:05:23Z",
                "disclosureTime": "2013-03-13T15:05:23Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Pádraic Brady"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 3.7,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70323",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70323",
                "title": "SQL Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to SQL Injection due to execution of platform-specific SQL containing interpolations.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.1.4, 2.0.8 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2013-03)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.1.0, <2.1.4",
                    ">=2, <2.0.8"
                  ]
                },
                "publicationTime": "2013-03-13T15:04:50Z",
                "disclosureTime": "2013-03-13T15:04:50Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-89"
                  ]
                },
                "credit": [
                  "Axel Helmert"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70324",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70324",
                "title": "IP Spoofing",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Potential IP Spoofing.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.2.5 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2013-04)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.2.5"
                  ]
                },
                "publicationTime": "2013-10-31T10:35:17Z",
                "disclosureTime": "2013-10-31T10:35:17Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-290"
                  ]
                },
                "credit": [
                  "Steve Talbot"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70325",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70325",
                "title": "XML External Entity (XXE) Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to XML External Entity (XXE) Injection.\n\n## Details\n\nXXE Injection is a type of attack against an application that parses XML input.\r\nXML is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. By default, many XML processors allow specification of an external entity, a URI that is dereferenced and evaluated during XML processing. When an XML document is being parsed, the parser can make a request and include the content at the specified URI inside of the XML document.\r\n\r\nAttacks can include disclosing local files, which may contain sensitive data such as passwords or private user data, using file: schemes or relative paths in the system identifier.\r\n\r\nFor example, below is a sample XML document, containing an XML element- username.\r\n\r\n```xml\r\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n   <username>John</username>\r\n</xml>\r\n```\r\n\r\nAn external XML entity - `xxe`, is defined using a system identifier and present within a DOCTYPE header. These entities can access local or remote content. For example the below code contains an external XML entity that would fetch the content of  `/etc/passwd` and display it to the user rendered by `username`.\r\n\r\n```xml\r\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n<!DOCTYPE foo [\r\n   <!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\r\n   <username>&xxe;</username>\r\n</xml>\r\n```\r\n\r\nOther XXE Injection attacks can access local resources that may not stop returning data, possibly impacting application availability and leading to Denial of Service.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.1.6, 2.2.6 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2014-01)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.1.0, <2.1.6",
                    ">=2.2.0, <2.2.6"
                  ]
                },
                "publicationTime": "2014-02-26T16:02:02Z",
                "disclosureTime": "2014-02-26T16:02:02Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-611"
                  ]
                },
                "credit": [
                  "Lukas Reschke"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70326",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70326",
                "title": "Cross-site Scripting (XSS)",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Cross-site Scripting (XSS).\n\n## Details\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\r\n\r\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\r\n\r\nֿInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\r\n\r\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\r\n \r\nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \r\n\r\n### Types of attacks\r\nThere are a few methods by which XSS can be manipulated:\r\n\r\n|Type|Origin|Description|\r\n|--|--|--|\r\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\r\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \r\n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\r\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\r\n\r\n### Affected environments\r\nThe following environments are susceptible to an XSS attack:\r\n\r\n* Web servers\r\n* Application servers\r\n* Web application environments\r\n\r\n### How to prevent\r\nThis section describes the top best practices designed to specifically protect your code: \r\n\r\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \r\n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \r\n* Give users the option to disable client-side scripts.\r\n* Redirect invalid requests.\r\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\r\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\r\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.1, 2.2.7 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2014-03)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.1",
                    ">=2, <2.2.7"
                  ]
                },
                "publicationTime": "2014-02-26T16:02:02Z",
                "disclosureTime": "2014-02-26T16:02:02Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-79"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "cvssScore": 6.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70327",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70327",
                "title": "Authentication Bypass",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Authentication Bypass.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.3, 2.2.8 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2014-05)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.3",
                    ">=2, <2.2.8"
                  ]
                },
                "publicationTime": "2014-09-16T22:00:00Z",
                "disclosureTime": "2014-09-16T22:00:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-8088"
                  ],
                  "CWE": [
                    "CWE-592"
                  ]
                },
                "credit": [
                  "Matthew Daley"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70328",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70328",
                "title": "SQL Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to SQL Injection vector when manually quoting values for sqlsrv extension, using null byte.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.3, 2.2.8 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2014-06)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.3",
                    ">=2, <2.2.8"
                  ]
                },
                "publicationTime": "2014-09-16T22:00:00Z",
                "disclosureTime": "2014-09-16T22:00:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2014-8089"
                  ],
                  "CWE": [
                    "CWE-89"
                  ]
                },
                "credit": [
                  "Jonas Sandström"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70329",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70329",
                "title": "Insufficient Session Validation",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Insufficient Session Validation.\n\n`Zend\\Session` session validators do not work as expected if set prior to the start of a session.\n\nThe implication is that subsequent calls to `Zend\\Session\\SessionManager#start()` (in later requests, assuming a session was created) will not have any validator metadata attached, which causes any validator metadata to be re-built from scratch, thus marking the session as valid.\n\nAn attacker is thus able to simply ignore session validators such as `RemoteAddr` or `HttpUserAgent`, since the \"signature\" that these validators check against is not being stored in the session.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.4, 2.2.9 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-01)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.4",
                    ">=2, <2.2.9"
                  ]
                },
                "publicationTime": "2015-01-14T22:00:00Z",
                "disclosureTime": "2015-01-14T22:00:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-284"
                  ]
                },
                "credit": [
                  "Yuriy Dyachenko"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70330",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70330",
                "title": "SQL Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to SQL Injection.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.5, 2.2.10 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-02)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2.3.0, <2.3.5",
                    ">=2, <2.2.10"
                  ]
                },
                "publicationTime": "2015-02-18T19:15:09Z",
                "disclosureTime": "2015-02-18T19:15:09Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-0270"
                  ],
                  "CWE": [
                    "CWE-89"
                  ]
                },
                "credit": [
                  "Grigory Ivanov"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70332",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70332",
                "title": "CRLF Injection",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Potential CRLF injection attacks in mail and HTTP headers.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.3.8, 2.4.1 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-04)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.3.8",
                    ">=2.4.0, <2.4.1"
                  ]
                },
                "publicationTime": "2015-05-07T08:53:42Z",
                "disclosureTime": "2015-05-07T08:53:42Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-3154"
                  ],
                  "CWE": [
                    "CWE-113"
                  ]
                },
                "credit": [
                  "Filippo Tessarotto",
                  "Maks3w"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70333",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70333",
                "title": "XML External Entity (XXE) Injection",
                "type": "vuln",
                "description": "## Overview\r\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to XML External Entity (XXE) Injection.\r\n\r\n## Details\r\n\r\nXXE Injection is a type of attack against an application that parses XML input.\r\nXML is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. By default, many XML processors allow specification of an external entity, a URI that is dereferenced and evaluated during XML processing. When an XML document is being parsed, the parser can make a request and include the content at the specified URI inside of the XML document.\r\n\r\nAttacks can include disclosing local files, which may contain sensitive data such as passwords or private user data, using file: schemes or relative paths in the system identifier.\r\n\r\nFor example, below is a sample XML document, containing an XML element- username.\r\n\r\n```xml\r\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n   <username>John</username>\r\n</xml>\r\n```\r\n\r\nAn external XML entity - `xxe`, is defined using a system identifier and present within a DOCTYPE header. These entities can access local or remote content. For example the below code contains an external XML entity that would fetch the content of  `/etc/passwd` and display it to the user rendered by `username`.\r\n\r\n```xml\r\n<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n<!DOCTYPE foo [\r\n   <!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\r\n   <username>&xxe;</username>\r\n</xml>\r\n```\r\n\r\nOther XXE Injection attacks can access local resources that may not stop returning data, possibly impacting application availability and leading to Denial of Service.\r\n\r\n## Remediation\r\nUpgrade `zendframework/zendframework` to version 2.4.6, 2.5.1 or higher.\r\n\r\n## References\r\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-06)",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "proof-of-concept",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.6",
                    ">=2.5.0, <2.5.1"
                  ]
                },
                "publicationTime": "2015-08-03T15:13:58Z",
                "disclosureTime": "2015-08-03T15:13:58Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-5161"
                  ],
                  "CWE": [
                    "CWE-611"
                  ]
                },
                "credit": [
                  "Dawid Golunski"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:O/RC:R",
                "cvssScore": 6.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70335",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70335",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Information Exposure.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.4.9 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-09)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "low",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.9"
                  ]
                },
                "publicationTime": "2015-11-23T14:30:00Z",
                "disclosureTime": "2015-11-23T14:30:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Vincent Herbulot"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 3.7,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70336",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70336",
                "title": "Information Exposure",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Information Exposure.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.4.9 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2015-10)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    ">=2, <2.4.9"
                  ]
                },
                "publicationTime": "2015-11-23T14:30:00Z",
                "disclosureTime": "2015-11-23T14:30:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [
                    "CVE-2015-7503"
                  ],
                  "CWE": [
                    "CWE-200"
                  ]
                },
                "credit": [
                  "Unknown"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cvssScore": 7.5,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70337",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-70337",
                "title": "Arbitrary Code Execution",
                "type": "vuln",
                "description": "## Overview\nAffected versions of [`zendframework/zendframework`](https://packagist.org/packages/zendframework/zendframework) are vulnerable to Arbitrary Code Execution.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.4.11 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2016-04)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "high",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.4.11"
                  ]
                },
                "publicationTime": "2016-12-19T15:29:00Z",
                "disclosureTime": "2016-12-19T15:29:00Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-94"
                  ]
                },
                "credit": [
                  "Dawid Golunski"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "cvssScore": 7.3,
                "patches": [],
                "upgradePath": []
              },
              {
                "id": "SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-72268",
                "url": "https://snyk.io/vuln/SNYK-PHP-ZENDFRAMEWORKZENDFRAMEWORK-72268",
                "title": "Arbitrary URL Rewrite",
                "type": "vuln",
                "description": "## Overview\n[zendframework/zendframework](https://packagist.org/packages/zendframework/zendframework) provides functionality for consuming RSS and Atom feeds.\n\nAffected versions of this package are vulnerable to Arbitrary URL Rewrite. The request URI marshaling process contains logic that inspects HTTP request headers that are specific to a given server-side URL rewrite mechanism. \n\nWhen these headers are present on systems not running the specific URL rewriting mechanism, the URLs are subject to rewriting, allowing a malicious client or proxy to emulate the headers to request arbitrary content.\n\n## Remediation\nUpgrade `zendframework/zendframework` to version 2.5.0 or higher.\n\n## References\n- [Zend Framework Security Advisory](https://framework.zend.com/security/advisory/ZF2018-01)\n",
                "functions": [],
                "from": [
                  "zendframework/zendframework@2.1.0"
                ],
                "package": "zendframework/zendframework",
                "version": "2.1.0",
                "severity": "medium",
                "exploitMaturity": "no-known-exploit",
                "language": "php",
                "packageManager": "composer",
                "semver": {
                  "vulnerable": [
                    "<2.5.0"
                  ]
                },
                "publicationTime": "2018-08-15T08:34:54.643000Z",
                "disclosureTime": "2018-08-02T16:29:46.707000Z",
                "isUpgradable": false,
                "isPatchable": false,
                "isPinnable": false,
                "identifiers": {
                  "CVE": [],
                  "CWE": [
                    "CWE-601"
                  ]
                },
                "credit": [
                  "Drupal Security Team"
                ],
                "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cvssScore": 5.3,
                "patches": [],
                "upgradePath": []
              }
            ],
            "licenses": []
          },
          "dependencyCount": 31,
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          },
          "licensesPolicy": null,
          "packageManager": "composer"
        }


## Dep Graph [/test/dep-graph{?org}]
Test for issues in a [Snyk dependency graph](https://github.com/snyk/dep-graph).

Experimental! Note these endpoints are subject to change and only available to selected users. Please
contact [support@snyk.io](mailto:support@snyk.io) to request access.

The following package managers are supported:

* deb
* gomodules
* gradle
* maven
* nuget
* paket
* pip
* rpm
* rubygems
* cocoapods
* npm
* yarn

### Test Dep Graph [POST /test/dep-graph{?org}]

Use this endpoint to find issues in a [DepGraph data object](https://github.com/snyk/dep-graph#depgraphdata).

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Project`
        + `View Project Snapshot`
        + `Test Project`

    + Headers

            Authorization: token API_KEY

    + Attributes (graph request payload)

    + Body

            {
              "depGraph": {
                "schemaVersion": "1.2.0",
                "pkgManager": {
                  "name": "maven"
                },
                "pkgs": [
                  {
                    "id": "app@1.0.0",
                    "info": {
                      "name": "app",
                      "version": "1.0.0"
                    }
                  },
                  {
                    "id": "ch.qos.logback:logback-core@1.0.13",
                    "info": {
                      "name": "ch.qos.logback:logback-core",
                      "version": "1.0.13"
                    }
                  }
                ],
                "graph": {
                  "rootNodeId": "root-node",
                  "nodes": [
                    {
                      "nodeId": "root-node",
                      "pkgId": "app@1.0.0",
                      "deps": [
                        {
                          "nodeId": "ch.qos.logback:logback-core@1.0.13"
                        }
                      ]
                    },
                    {
                      "nodeId": "ch.qos.logback:logback-core@1.0.13",
                      "pkgId": "ch.qos.logback:logback-core@1.0.13",
                      "deps": []
                    }
                  ]
                }
              }
            }


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": false,
          "packageManager": "maven",
          "issuesData": {
            "SNYK-JAVA-CHQOSLOGBACK-30208": {
              "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "credit": [
                "Unknown"
              ],
              "cvssScore": 9.8,
              "description": "## Overview\n\n[ch.qos.logback:logback-core](https://mvnrepository.com/artifact/ch.qos.logback/logback-core) is a logback-core module.\n\n\nAffected versions of this package are vulnerable to Arbitrary Code Execution.\nA configuration can be turned on to allow remote logging through interfaces that accept untrusted serialized data. Authenticated attackers on the adjacent network can exploit this vulnerability to run arbitrary code through the deserialization of custom gadget chains.\n\n## Details\nSerialization is a process of converting an object into a sequence of bytes which can be persisted to a disk or database or can be sent through streams. The reverse process of creating object from sequence of bytes is called deserialization. Serialization is commonly used for communication (sharing objects between multiple hosts) and persistence (store the object state in a file or a database). It is an integral part of popular protocols like _Remote Method Invocation (RMI)_, _Java Management Extension (JMX)_, _Java Messaging System (JMS)_, _Action Message Format (AMF)_, _Java Server Faces (JSF) ViewState_, etc.\r\n\r\n  \r\n\r\n_Deserialization of untrusted data_ ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), is when the application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, letting the attacker to control the state or the flow of the execution.\r\n\r\n  \r\n\r\nJava deserialization issues have been known for years. However, interest in the issue intensified greatly in 2015, when classes that could be abused to achieve remote code execution were found in a [popular library (Apache Commons Collection)](https://snyk.io/vuln/SNYK-JAVA-COMMONSCOLLECTIONS-30078). These classes were used in zero-days affecting IBM WebSphere, Oracle WebLogic and many other products.\r\n\r\n  \r\n\r\nAn attacker just needs to identify a piece of software that has both a vulnerable class on its path, and performs deserialization on untrusted data. Then all they need to do is send the payload into the deserializer, getting the command executed.\r\n\r\n  \r\n\r\n> Developers put too much trust in Java Object Serialization. Some even de-serialize objects pre-authentication. When deserializing an Object in Java you typically cast it to an expected type, and therefore Java's strict type system will ensure you only get valid object trees. Unfortunately, by the time the type checking happens, platform code has already created and executed significant logic. So, before the final type is checked a lot of code is executed from the readObject() methods of various objects, all of which is out of the developer's control. By combining the readObject() methods of various classes which are available on the classpath of the vulnerable application an attacker can execute functions (including calling Runtime.exec() to execute local OS commands).\r\n\r\n- Apache Blog\r\n\r\n  \r\n\r\nThe vulnerability, also know as _Mad Gadget_\r\n\r\n> Mad Gadget is one of the most pernicious vulnerabilities we’ve seen. By merely existing on the Java classpath, seven “gadget” classes in Apache Commons Collections (versions 3.0, 3.1, 3.2, 3.2.1, and 4.0) make object deserialization for the entire JVM process Turing complete with an exec function. Since many business applications use object deserialization to send messages across the network, it would be like hiring a bank teller who was trained to hand over all the money in the vault if asked to do so politely, and then entrusting that teller with the key. The only thing that would keep a bank safe in such a circumstance is that most people wouldn’t consider asking such a question.\r\n\r\n- Google\n\n## Remediation\n\nUpgrade `ch.qos.logback:logback-core` to version 1.1.11 or higher.\n\n\n## References\n\n- [Logback News](https://logback.qos.ch/news.html)\n\n- [NVD](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5929/)\n",
              "disclosureTime": "2017-03-13T06:59:00Z",
              "fixedIn": [
                "1.1.11"
              ],
              "id": "SNYK-JAVA-CHQOSLOGBACK-30208",
              "identifiers": {
                "CVE": [
                  "CVE-2017-5929"
                ],
                "CWE": [
                  "CWE-502"
                ]
              },
              "language": "java",
              "mavenModuleName": {
                "artifactId": "logback-core",
                "groupId": "ch.qos.logback"
              },
              "moduleName": "ch.qos.logback:logback-core",
              "packageManager": "maven",
              "packageName": "ch.qos.logback:logback-core",
              "patches": [],
              "semver": {
                "vulnerable": [
                  "[, 1.1.11)"
                ]
              },
              "severity": "critical",
              "title": "Arbitrary Code Execution"
            }
          },
          "issues": [
            {
              "pkgName": "ch.qos.logback:logback-core",
              "pkgVersion": "1.0.13",
              "issueId": "SNYK-JAVA-CHQOSLOGBACK-30208",
              "fixInfo": {}
            }
          ],
          "org": {
            "name": "atokeneduser",
            "id": "4a18d42f-0706-4ad0-b127-24078731fbed"
          }
        }


# Data Structures

## Vulnerability (object)
+ title (string) - The title of the vulnerability
+ credit (object) - The reporter of the vulnerability
+ description (string) - The description of the vulnerability
+ semver (SemverObject) - Versions affected by this issue
+ CVSSv3 (string) - Common Vulnerability Scoring System (CVSS) provides a way to capture the principal characteristics of a vulnerability, and produce a numerical score reflecting its severity, as well as a textual representation of that score.
+ severity (string) - Snyk severity for this issue. One of: `critical`, `medium`, `high`, `medium` or `low`.
+ exploitMaturity (string) - Snyk exploit maturity for this issue. One of: `mature`, `proof-of-concept`, `no-known-exploit` or `no-data`.
+ identifiers (object) - Additional identifiers for this issue (CVE, CWE, etc).
+ patches (array[Patch]) - Patches to fix this issue, by Snyk.
+ packageName (string) - The name of the vulnerable package.
+ creationTime (string)
+ publicationTime (string)
+ modificationTime (string)
+ disclosureTime (string)
+ language (string) - The programming language for this package.
+ packageManager `npm` (string)
+ functions (array[Function]) - List of vulnerable functions inside the vulnerable packages.
+ cvssScore (number) - CVSS Score.
+ alternativeIds (object)
+ from (object) - Paths from which the vulnerable package is required in the code base.
+ upgradePath (object)
+ isUpgradable (boolean) - Will upgrading a top-level dependency fix the vulnerability?
+ isPinnable (boolean) - Will pinning this package to a newer version fix the vulnerability?
+ isPatchable (boolean) - Is a patch by Snyk available to fix this vulnerability?

## Maven request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (MavenFile, required) - the main/root manifest file, encoded according the the "encoding" field.

    + additional (array[MavenAdditionalFile], optional) - additional manifest files (if needed), encoded according the the "encoding" field.


## govendor request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `vendor.json` file, encoded according the the "encoding" field.
        + contents: `{\"comment\":\"\",\"ignore\":\"test\",\"package\":[{\"checksumSHA1\":\"o/3cn04KAiwC7NqNVvmfVTD+hgA=\",\"path\":\"github.com/Microsoft/go-winio\",\"revision\":\"78439966b38d69bf38227fbf57ac8a6fee70f69a\",\"revisionTime\":\"2017-08-04T20:09:54Z\"},{\"checksumSHA1\":\"GqIrOttKaO7k6HIaHQLPr3cY7rY=\",\"path\":\"github.com/containerd/continuity/pathdriver\",\"revision\":\"617902de2ab5e18974efd88a58eeef67ac82d127\",\"revisionTime\":\"2017-09-25T16:43:31Z\"},{\"checksumSHA1\":\"ndnAFCfsGC3upNQ6jAEwzxcurww=\",\"path\":\"github.com/docker/docker/pkg/longpath\",\"revision\":\"74a084162ce544fe995715ba47aa84d3d75b95c1\",\"revisionTime\":\"2017-09-26T16:09:50Z\"},{\"checksumSHA1\":\"IVWozKA/coqhti24Ss2b1nLrTSg=\",\"path\":\"github.com/docker/docker/pkg/mount\",\"revision\":\"74a084162ce544fe995715ba47aa84d3d75b95c1\",\"revisionTime\":\"2017-09-26T16:09:50Z\"},{\"checksumSHA1\":\"YdUAOhhc/C0zu+eYrJOJjDwr1/4=\",\"path\":\"github.com/docker/docker/pkg/symlink\",\"revision\":\"74a084162ce544fe995715ba47aa84d3d75b95c1\",\"revisionTime\":\"2017-09-26T16:09:50Z\"},{\"checksumSHA1\":\"UEMAKQqAyL9hs6RWxesQuYMQ3+I=\",\"path\":\"github.com/docker/docker/pkg/system\",\"revision\":\"74a084162ce544fe995715ba47aa84d3d75b95c1\",\"revisionTime\":\"2017-09-26T16:09:50Z\"},{\"checksumSHA1\":\"UmXGieuTJQOzJPspPJTVKKKMiUA=\",\"path\":\"github.com/docker/go-units\",\"revision\":\"0dadbb0345b35ec7ef35e228dabb8de89a65bf52\",\"revisionTime\":\"2017-01-27T09:51:30Z\"},{\"checksumSHA1\":\"RCARG9BoOH6jwbqnuix2Ne3K26w=\",\"path\":\"github.com/docker/libcontainer\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"OVGl5SGmF1HZmaG6JRmkyWiycYA=\",\"path\":\"github.com/docker/libcontainer/cgroups\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"q56oWh80PeIBiE/8nQ/Emz18ZZ8=\",\"path\":\"github.com/docker/libcontainer/cgroups/fs\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"3NQtWwKOT4BlnSWn0tTsy/N+XhU=\",\"path\":\"github.com/docker/libcontainer/console\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"WPIuCuWS1RkrGCHBRZuOJku7ZBc=\",\"path\":\"github.com/docker/libcontainer/devices\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"HLo2E8AWKNCwE2p7ndEkKc4SPnM=\",\"path\":\"github.com/docker/libcontainer/label\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"KYcr4bHkervvLS5wuH9w1+EhflY=\",\"path\":\"github.com/docker/libcontainer/mount\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"tvHnvhbm17pLR/fA2WXWYlY9aDs=\",\"path\":\"github.com/docker/libcontainer/mount/nodes\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"k9+kwIouq8vqmodLrGFp+9I7Jxs=\",\"path\":\"github.com/docker/libcontainer/netlink\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"ndpCrSi/XKZNCCrkjpQ2cgMIxKA=\",\"path\":\"github.com/docker/libcontainer/network\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"cfgnX7wKfSHOJ4mbhKyjAWizl+s=\",\"path\":\"github.com/docker/libcontainer/selinux\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"M7/2WUk1uzgdqc5Ce/k9UcSyv1M=\",\"path\":\"github.com/docker/libcontainer/system\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"2ZMmNaPI3TM4WyMjCw+h1jErSr0=\",\"path\":\"github.com/docker/libcontainer/utils\",\"revision\":\"53eca435e63db58b06cf796d3a9326db5fd42253\",\"revisionTime\":\"2014-12-02T23:28:38Z\",\"version\":\"v1.4\",\"versionExact\":\"v1.4.0\"},{\"checksumSHA1\":\"rJab1YdNhQooDiBWNnt7TLWPyBU=\",\"path\":\"github.com/pkg/errors\",\"revision\":\"2b3a18b5f0fb6b4f9190549597d3f962c02bc5eb\",\"revisionTime\":\"2017-09-10T13:46:14Z\"},{\"checksumSHA1\":\"BYvROBsiyAXK4sq6yhDe8RgT4LM=\",\"path\":\"github.com/sirupsen/logrus\",\"revision\":\"89742aefa4b206dcf400792f3bd35b542998eb3b\",\"revisionTime\":\"2017-08-22T13:27:46Z\"},{\"checksumSHA1\":\"nqWNlnMmVpt628zzvyo6Yv2CX5Q=\",\"path\":\"golang.org/x/crypto/ssh/terminal\",\"revision\":\"847319b7fc94cab682988f93da778204da164588\",\"revisionTime\":\"2017-08-18T09:57:21Z\"},{\"checksumSHA1\":\"uggjqMBFNJd11oNco2kbkAT641w=\",\"path\":\"golang.org/x/sys/unix\",\"revision\":\"429f518978ab01db8bb6f44b66785088e7fba58b\",\"revisionTime\":\"2017-09-20T21:38:28Z\"},{\"checksumSHA1\":\"pBPFzDGt3AVSRffB7ffiUnruFUk=\",\"path\":\"golang.org/x/sys/windows\",\"revision\":\"429f518978ab01db8bb6f44b66785088e7fba58b\",\"revisionTime\":\"2017-09-20T21:38:28Z\"},{\"checksumSHA1\":\"o5NrWoSkC+ugoK9D6ragLSrXHw0=\",\"path\":\"gopkg.in/square/go-jose.v2\",\"revision\":\"296c7f1463ec9b712176dc804dea0173d06dc728\",\"revisionTime\":\"2016-11-17T00:42:38Z\",\"version\":\"v2.0\",\"versionExact\":\"v2.0.1\"},{\"checksumSHA1\":\"j94zYNLTvPSnfnqVKJ4LUf++uX4=\",\"path\":\"gopkg.in/square/go-jose.v2/cipher\",\"revision\":\"296c7f1463ec9b712176dc804dea0173d06dc728\",\"revisionTime\":\"2016-11-17T00:42:38Z\",\"version\":\"v2.0\",\"versionExact\":\"v2.0.1\"},{\"checksumSHA1\":\"JFun0lWY9eqd80Js2iWsehu1gc4=\",\"path\":\"gopkg.in/square/go-jose.v2/json\",\"revision\":\"296c7f1463ec9b712176dc804dea0173d06dc728\",\"revisionTime\":\"2016-11-17T00:42:38Z\",\"version\":\"v2.0\",\"versionExact\":\"v2.0.1\"}],\"rootPath\":\"with-vuln\"}`


## golangdep request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `Gopkg.toml` file, encoded according the the "encoding" field.
        + contents: `"# Gopkg.toml example\r\n#\r\n# Refer to https://golang.github.io/dep/docs/Gopkg.toml.html\r\n# for detailed Gopkg.toml documentation.\r\n#\r\n# required = [\"github.com/user/thing/cmd/thing\"]\r\n# ignored = [\"github.com/user/project/pkgX\", \"bitbucket.org/user/project/pkgA/pkgY\"]\r\n#\r\n# [[constraint]]\r\n#   name = \"github.com/user/project\"\r\n#   version = \"1.0.0\"\r\n#\r\n# [[constraint]]\r\n#   name = \"github.com/user/project2\"\r\n#   branch = \"dev\"\r\n#   source = \"github.com/myfork/project2\"\r\n#\r\n# [[override]]\r\n#   name = \"github.com/x/y\"\r\n#   version = \"2.4.0\"\r\n#\r\n# [prune]\r\n#   non-go = false\r\n#   go-tests = true\r\n#   unused-packages = true\r\n\r\n\r\n[[constraint]]\r\n  branch = \"master\"\r\n  name = \"github.com/asaskevich/EventBus\"\r\n\r\n[[constraint]]\r\n  branch = \"master\"\r\n  name = \"github.com/cloudevents/sdk-go\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/gin-gonic/gin\"\r\n  version = \"1.3.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/golang/protobuf\"\r\n  version = \"1.2.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/goph/emperror\"\r\n  version = \"0.14.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/goph/logur\"\r\n  version = \"0.5.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/patrickmn/go-cache\"\r\n  version = \"2.1.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/pkg/errors\"\r\n  version = \"0.8.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/satori/go.uuid\"\r\n  version = \"1.2.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/sirupsen/logrus\"\r\n  version = \"1.2.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/spf13/cast\"\r\n  version = \"1.3.0\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/spf13/pflag\"\r\n  version = \"1.0.3\"\r\n\r\n[[constraint]]\r\n  name = \"github.com/spf13/viper\"\r\n  version = \"1.3.1\"\r\n\r\n[[constraint]]\r\n  branch = \"master\"\r\n  name = \"golang.org/x/net\"\r\n\r\n[[constraint]]\r\n  name = \"google.golang.org/grpc\"\r\n  version = \"1.17.0\"\r\n\r\n[[constraint]]\r\n  name = \"gopkg.in/go-playground/validator.v8\"\r\n  version = \"8.18.2\"\r\n\r\n[[constraint]]\r\n  name = \"gopkg.in/yaml.v2\"\r\n  version = \"2.2.2\"\r\n\r\n[prune]\r\n  go-tests = true\r\n  unused-packages = true"`
    + additional (array[GoPkgLock], required) - a lockfile encoded according the the "encoding" field.


## npm request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `package.json` file, encoded according the the "encoding" field.
        + contents: `eyAibmFtZSI6ICJzaGFsbG93LWdvb2YiLCAidmVyc2lvbiI6ICIwLjAuMSIsICJkZXNjcmlwdGlvbiI6ICJBIHZ1bG5lcmFibGUgZGVtbyBhcHBsaWNhdGlvbiIsICJob21lcGFnZSI6ICJodHRwczovL3NueWsuaW8vIiwgInJlcG9zaXRvcnkiOiB7ICJ0eXBlIjogImdpdCIsICJ1cmwiOiAiaHR0cHM6Ly9naXRodWIuY29tL1NueWsvc2hhbGxvdy1nb29mIiB9LCAiZGVwZW5kZW5jaWVzIjogeyAibm9kZS11dWlkIjogIjEuNC4wIiwgInFzIjogIjAuMC42IiB9IH0K` (string, required) - the contents of `package.json` as a string.
    + additional (array[PackageLockJsonFile], optional) - a lockfile can be sent (if needed), encoded according the the "encoding" field.

## yarn request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `plain`

+ files (object, required) - The manifest files:
    + target (object, required) - the `package.json` file, encoded according the the "encoding" field.
        + contents: `{ "name": "shallow-goof", "version": "0.0.1", "description": "A vulnerable demo application", "homepage": "https://snyk.io/", "repository": { "type": "git", "url": "https://github.com/Snyk/shallow-goof" }, "dependencies": { "node-uuid": "1.4.0", "qs": "0.0.6" } }` (string, required) - the contents of `package.json` as a string.
    + additional (array[YarnLockFile], optional) - a lockfile can be sent (if needed), encoded according the the "encoding" field.

## rubygems request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `Gemfile.lock` file, encoded according the the "encoding" field.
        + contents: `GEM\n remote: http://rubygems.org/\n specs:\n actionpack (4.2.5)\n actionview (= 4.2.5)\n activesupport (= 4.2.5)\n rack (~> 1.6)\n rack-test (~> 0.6.2)\n rails-dom-testing (~> 1.0, >= 1.0.5)\n rails-html-sanitizer (~> 1.0, >= 1.0.2)\n actionview (4.2.5)\n activesupport (= 4.2.5)\n builder (~> 3.1)\n erubis (~> 2.7.0)\n rails-dom-testing (~> 1.0, >= 1.0.5)\n rails-html-sanitizer (~> 1.0, >= 1.0.2)\n activesupport (4.2.5)\n i18n (~> 0.7)\n json (~> 1.7, >= 1.7.7)\n minitest (~> 5.1)\n thread_safe (~> 0.3, >= 0.3.4)\n tzinfo (~> 1.1)\n builder (3.2.2)\n erubis (2.7.0)\n haml (3.1.4)\n httparty (0.8.1)\n multi_json\n multi_xml\n i18n (0.7.0)\n json (1.8.3)\n loofah (2.0.3)\n nokogiri (>= 1.5.9)\n mini_portile2 (2.1.0)\n minitest (5.9.1)\n multi_json (1.12.1)\n multi_xml (0.5.5)\n nokogiri (1.6.8.1)\n mini_portile2 (~> 2.1.0)\n rack (1.6.4)\n rack-protection (1.5.3)\n rack\n rack-test (0.6.3)\n rack (>= 1.0)\n rails-deprecated_sanitizer (1.0.3)\n activesupport (>= 4.2.0.alpha)\n rails-dom-testing (1.0.7)\n activesupport (>= 4.2.0.beta, < 5.0)\n nokogiri (~> 1.6.0)\n rails-deprecated_sanitizer (>= 1.0.1)\n rails-html-sanitizer (1.0.3)\n loofah (~> 2.0)\n sinatra (1.3.2)\n rack (~> 1.3, >= 1.3.6)\n rack-protection (~> 1.2)\n tilt (~> 1.3, >= 1.3.3)\n thread_safe (0.3.5)\n tilt (1.4.1)\n tzinfo (1.2.2)\n thread_safe (~> 0.1)\n \n PLATFORMS\n ruby\n \n DEPENDENCIES\n actionpack\n haml\n httparty\n sinatra\n \n BUNDLED WITH\n 1.13.2` (string, required) - the contents of `Gemfile.lock` as a string.

## Gradle request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (GradleFile, required) - the manifest file, encoded according the the "encoding" field.

## sbt request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`


+ files (object, required) - The manifest files:
    + target (SBTFile, required) - the manifest file, encoded according the the "encoding" field.

## pip request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `requirements.txt` file, encoded according the the "encoding" field.
        + contents: `supervisor==3.1\noauth2==1.5.211` (string, required) - the contents of `requirements.txt` as a string, encoded according to `encoding` above.

## composer request payload
+ encoding (optional, enum[string]) - the encoding for the manifest files sent.
    + Members
        + `plain`
        + `base64`

    + Default
        + `base64`

+ files (object, required) - The manifest files:
    + target (object, required) - the `composer.json` file, encoded according the the "encoding" field.
        + contents: `{"name": "vulnerable/project","description": "A sample vulnerable project","require": {"php": ">=5.3.2","symfony/symfony": "v2.3.1","yiisoft/yii": "1.1.14","zendframework/zendframework": "2.1.0","aws/aws-sdk-php": "3.0.0","doctrine/common": "2.5.0"}}`
    + additional (array[ComposerLock], required) - a lockfile encoded according the the "encoding" field.

## graph request payload
+ depGraph (DepGraphData, required) - A [DepGraph data object](https://github.com/snyk/dep-graph#depgraphdata) defining all packages and their relationships.

## SemverObject (object)
+ vulnerable (string) - The (semver) range of versions vulnerable to this issue.
+ unaffected (string) - The (semver) range of versions NOT vulnerable to this issue. *Deprecated* and should not be used.

## Patch (object)
+ urls (array[string]) - Links to patch files to fix an issue.
+ version (string) - Versions this patch is applicable to, in semver format.
+ modificationTime (string)
+ comments (array[string])
+ id (string)

## Function (object)
+ functionId (FunctionId) - Class and function names.
+ version (array[string]) - Versions this function relates to.

## FunctionId (object)
+ functionName (string) - Function name.
+ className? (string) - Class name (Java only).
+ filePath? (string) - Path to file (Javascript only).

## MavenFile (object)
+ contents: `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"> <modelVersion>4.0.0</modelVersion> <parent> <artifactId>io.snyk.example</artifactId> <groupId>parent</groupId> <version>1.0-SNAPSHOT</version> </parent> <artifactId>my-project</artifactId> <dependencies> <dependency> <groupId>axis</groupId> <artifactId>axis</artifactId> <version>1.4</version> </dependency> </dependencies> </project>\n` (string, required) - The contents of the file, encoded according to the `encoding` field.

## MavenAdditionalFile (object)
+ contents: `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"> <modelVersion>4.0.0</modelVersion> <artifactId>io.snyk.example</artifactId> <groupId>parent</groupId> <version>1.0-SNAPSHOT</version> <dependencies> <dependency> <groupId>org.apache.zookeeper</groupId> <artifactId>zookeeper</artifactId> <version>3.5</version> </dependency> <dependency> <groupId>org.aspectj</groupId> <artifactId>aspectjweaver</artifactId> <version>1.8.2</version> </dependency> </dependencies> </project>\n` (string, required) - The contents of the file, encoded according to the `encoding` field.

## GradleFile (object)
+ contents: `dependencies { compile 'axis:axis:1.4' }` (string, required) - The contents of the file, encoded according to the `encoding` field.

## SBTFile (object)
+ contents: `\nname := \"subsearch\"\n\nassemblyJarName in assembly := s\"subsearch-0.2.0.jar\"\n\nscalaVersion := \"2.11.8\"\n\nscalacOptions ++= Seq(\"-unchecked\", \"-deprecation\")\n\nresolvers += Resolver.sonatypeRepo(\"public\")\n\nlibraryDependencies += \"org.scalatest\" % \"scalatest_2.11\" % \"2.2.1\" % \"test\"\nlibraryDependencies += \"org.scalamock\" %% \"scalamock-scalatest-support\" % \"3.2.2\" % \"test\"\nlibraryDependencies += \"net.databinder.dispatch\" %% \"dispatch-core\" % \"0.11.2\"\nlibraryDependencies += \"org.slf4j\" % \"slf4j-simple\" % \"1.6.6\"\nlibraryDependencies += \"com.github.scopt\" %% \"scopt\" % \"3.4.0\"\nlibraryDependencies += \"pl.project13.scala\" %% \"rainbow\" % \"0.2\"\nlibraryDependencies += \"dnsjava\" % \"dnsjava\" % \"2.1.7\"\nlibraryDependencies += \"com.typesafe.akka\" %% \"akka-actor\" % \"2.4.1\"\nlibraryDependencies += \"org.scala-lang.modules\" % \"scala-jline\" % \"2.12.1\"\nlibraryDependencies += \"net.ruippeixotog\" %% \"scala-scraper\" % \"1.0.0\"` (string, required) - The contents of the file, encoded according to the `encoding` field.

## PackageLockJsonFile (object)
+ contents: `eyAibmFtZSI6ICJzaGFsbG93LWdvb2YiLCAidmVyc2lvbiI6ICIwLjAuMSIsICJsb2NrZmlsZVZlcnNpb24iOiAxLCAicmVxdWlyZXMiOiB0cnVlLCAiZGVwZW5kZW5jaWVzIjogeyAibm9kZS11dWlkIjogeyAidmVyc2lvbiI6ICIxLjQuMCIsICJyZXNvbHZlZCI6ICJodHRwczovL3JlZ2lzdHJ5Lm5wbWpzLm9yZy9ub2RlLXV1aWQvLS9ub2RlLXV1aWQtMS40LjAudGd6IiwgImludGVncml0eSI6ICJzaGExLUIvbXlNM1Z5LzJKMXgzWGgxSVVUODZSZGVtVT0iIH0sICJxcyI6IHsgInZlcnNpb24iOiAiMC4wLjYiLCAicmVzb2x2ZWQiOiAiaHR0cHM6Ly9yZWdpc3RyeS5ucG1qcy5vcmcvcXMvLS9xcy0wLjAuNi50Z3oiLCAiaW50ZWdyaXR5IjogInNoYTEtU0JaWnQrVy9hbDZvbUFFTjVhN1RYclJwNFNRPSIgfSB9IH0K` (string, optional) - The contents of the file, encoded according to the `encoding` field.

## YarnLockFile (object)
+ contents: `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\r\n# yarn lockfile v1\r\n\r\n\r\nnode-uuid@1.4.0:\r\n  version \"1.4.0\"\r\n  resolved \"https:\/\/registry.yarnpkg.com\/node-uuid\/-\/node-uuid-1.4.0.tgz#07f9b2337572ff6275c775e1d48513f3a45d7a65\"\r\n  integrity sha1-B\/myM3Vy\/2J1x3Xh1IUT86RdemU=\r\n\r\nqs@0.0.6:\r\n  version \"0.0.6\"\r\n  resolved \"https:\/\/registry.yarnpkg.com\/qs\/-\/qs-0.0.6.tgz#481659b7e5bf6a5ea898010de5aed35eb469e124\"\r\n  integrity sha1-SBZZt+W\/al6omAEN5a7TXrRp4SQ=\r\n`

## GoPkgLock (object)
+ contents: `"# This file is autogenerated, do not edit; changes may be undone by the next 'dep ensure'.\r\n\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:e2a1ff1174d564ed4b75a62757f4a9081ed3b8c99ed17e47eb252b048b4ff018\"\r\n  name = \"github.com/asaskevich/EventBus\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"d46933a94f05c6657d7b923fcf5ac563ee37ec79\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:b95c3763b72359370262246870366418c1d17446195e3c73921135c2537b9655\"\r\n  name = \"github.com/cloudevents/sdk-go\"\r\n  packages = [\r\n    \".\",\r\n    \"v02\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"3a3d34a7231e937edfa20964dc25c29081c3ebea\"\r\n\r\n[[projects]]\r\n  digest = \"1:abeb38ade3f32a92943e5be54f55ed6d6e3b6602761d74b4aab4c9dd45c18abd\"\r\n  name = \"github.com/fsnotify/fsnotify\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"c2828203cd70a50dcccfb2761f8b1f8ceef9a8e9\"\r\n  version = \"v1.4.7\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:36fe9527deed01d2a317617e59304eb2c4ce9f8a24115bcc5c2e37b3aee5bae4\"\r\n  name = \"github.com/gin-contrib/sse\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"22d885f9ecc78bf4ee5d72b937e4bbcdc58e8cae\"\r\n\r\n[[projects]]\r\n  digest = \"1:d5083934eb25e45d17f72ffa86cae3814f4a9d6c073c4f16b64147169b245606\"\r\n  name = \"github.com/gin-gonic/gin\"\r\n  packages = [\r\n    \".\",\r\n    \"binding\",\r\n    \"json\",\r\n    \"render\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"b869fe1415e4b9eb52f247441830d502aece2d4d\"\r\n  version = \"v1.3.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:4c0989ca0bcd10799064318923b9bc2db6b4d6338dd75f3f2d86c3511aaaf5cf\"\r\n  name = \"github.com/golang/protobuf\"\r\n  packages = [\r\n    \"proto\",\r\n    \"ptypes\",\r\n    \"ptypes/any\",\r\n    \"ptypes/duration\",\r\n    \"ptypes/timestamp\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"aa810b61a9c79d51363740d207bb46cf8e620ed5\"\r\n  version = \"v1.2.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:4e0e5d786c35c402574cda1906195d9fbd76a35d2c921eb10199741faf4f0256\"\r\n  name = \"github.com/goph/emperror\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"b1b4a9b847ebc56299eb729faa942b89e9d8a562\"\r\n  version = \"v0.14.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:dd95856542089c3e0487299d6ac92f5f2941e97625b5a5754a483c7730e8dc89\"\r\n  name = \"github.com/goph/logur\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"111a952ccfacab0a90b9e4496da21d9f15187769\"\r\n  version = \"v0.5.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:c0d19ab64b32ce9fe5cf4ddceba78d5bc9807f0016db6b1183599da3dcc24d10\"\r\n  name = \"github.com/hashicorp/hcl\"\r\n  packages = [\r\n    \".\",\r\n    \"hcl/ast\",\r\n    \"hcl/parser\",\r\n    \"hcl/printer\",\r\n    \"hcl/scanner\",\r\n    \"hcl/strconv\",\r\n    \"hcl/token\",\r\n    \"json/parser\",\r\n    \"json/scanner\",\r\n    \"json/token\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"8cb6e5b959231cc1119e43259c4a608f9c51a241\"\r\n  version = \"v1.0.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:be97e109f627d3ba8edfef50c9c74f0d0c17cbe3a2e924a8985e4804a894f282\"\r\n  name = \"github.com/json-iterator/go\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"36b14963da70d11297d313183d7e6388c8510e1e\"\r\n  version = \"1.0.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:0a69a1c0db3591fcefb47f115b224592c8dfa4368b7ba9fae509d5e16cdc95c8\"\r\n  name = \"github.com/konsorten/go-windows-terminal-sequences\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"5c8c8bd35d3832f5d134ae1e1e375b69a4d25242\"\r\n  version = \"v1.0.1\"\r\n\r\n[[projects]]\r\n  digest = \"1:c568d7727aa262c32bdf8a3f7db83614f7af0ed661474b24588de635c20024c7\"\r\n  name = \"github.com/magiconair/properties\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"c2353362d570a7bfa228149c62842019201cfb71\"\r\n  version = \"v1.8.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:fa610f9fe6a93f4a75e64c83673dfff9bf1a34bbb21e6102021b6bc7850834a3\"\r\n  name = \"github.com/mattn/go-isatty\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"57fdcb988a5c543893cc61bce354a6e24ab70022\"\r\n\r\n[[projects]]\r\n  digest = \"1:53bc4cd4914cd7cd52139990d5170d6dc99067ae31c56530621b18b35fc30318\"\r\n  name = \"github.com/mitchellh/mapstructure\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"3536a929edddb9a5b34bd6861dc4a9647cb459fe\"\r\n  version = \"v1.1.2\"\r\n\r\n[[projects]]\r\n  digest = \"1:808cdddf087fb64baeae67b8dfaee2069034d9704923a3cb8bd96a995421a625\"\r\n  name = \"github.com/patrickmn/go-cache\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"a3647f8e31d79543b2d0f0ae2fe5c379d72cedc0\"\r\n  version = \"v2.1.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:95741de3af260a92cc5c7f3f3061e85273f5a81b5db20d4bd68da74bd521675e\"\r\n  name = \"github.com/pelletier/go-toml\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"c01d1270ff3e442a8a57cddc1c92dc1138598194\"\r\n  version = \"v1.2.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:40e195917a951a8bf867cd05de2a46aaf1806c50cf92eebf4c16f78cd196f747\"\r\n  name = \"github.com/pkg/errors\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"645ef00459ed84a119197bfb8d8205042c6df63d\"\r\n  version = \"v0.8.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:274f67cb6fed9588ea2521ecdac05a6d62a8c51c074c1fccc6a49a40ba80e925\"\r\n  name = \"github.com/satori/go.uuid\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"f58768cc1a7a7e77a3bd49e98cdd21419399b6a3\"\r\n  version = \"v1.2.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:69b1cc331fca23d702bd72f860c6a647afd0aa9fcbc1d0659b1365e26546dd70\"\r\n  name = \"github.com/sirupsen/logrus\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"bcd833dfe83d3cebad139e4a29ed79cb2318bf95\"\r\n  version = \"v1.2.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:d707dbc1330c0ed177d4642d6ae102d5e2c847ebd0eb84562d0dc4f024531cfc\"\r\n  name = \"github.com/spf13/afero\"\r\n  packages = [\r\n    \".\",\r\n    \"mem\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"a5d6946387efe7d64d09dcba68cdd523dc1273a3\"\r\n  version = \"v1.2.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:08d65904057412fc0270fc4812a1c90c594186819243160dc779a402d4b6d0bc\"\r\n  name = \"github.com/spf13/cast\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"8c9545af88b134710ab1cd196795e7f2388358d7\"\r\n  version = \"v1.3.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:68ea4e23713989dc20b1bded5d9da2c5f9be14ff9885beef481848edd18c26cb\"\r\n  name = \"github.com/spf13/jwalterweatherman\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"4a4406e478ca629068e7768fc33f3f044173c0a6\"\r\n  version = \"v1.0.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:c1b1102241e7f645bc8e0c22ae352e8f0dc6484b6cb4d132fa9f24174e0119e2\"\r\n  name = \"github.com/spf13/pflag\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"298182f68c66c05229eb03ac171abe6e309ee79a\"\r\n  version = \"v1.0.3\"\r\n\r\n[[projects]]\r\n  digest = \"1:de37e343c64582d7026bf8ab6ac5b22a72eac54f3a57020db31524affed9f423\"\r\n  name = \"github.com/spf13/viper\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"6d33b5a963d922d182c91e8a1c88d81fd150cfd4\"\r\n  version = \"v1.3.1\"\r\n\r\n[[projects]]\r\n  digest = \"1:c268acaa4a4d94a467980e5e91452eb61c460145765293dc0aed48e5e9919cc6\"\r\n  name = \"github.com/ugorji/go\"\r\n  packages = [\"codec\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"c88ee250d0221a57af388746f5cf03768c21d6e2\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:38f553aff0273ad6f367cb0a0f8b6eecbaef8dc6cb8b50e57b6a81c1d5b1e332\"\r\n  name = \"golang.org/x/crypto\"\r\n  packages = [\"ssh/terminal\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"505ab145d0a99da450461ae2c1a9f6cd10d1f447\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:89a0cb976397aa9157a45bb2b896d0bcd07ee095ac975e0f03c53250c402265e\"\r\n  name = \"golang.org/x/net\"\r\n  packages = [\r\n    \"context\",\r\n    \"http/httpguts\",\r\n    \"http2\",\r\n    \"http2/hpack\",\r\n    \"idna\",\r\n    \"internal/timeseries\",\r\n    \"trace\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"e147a9138326bc0e9d4e179541ffd8af41cff8a9\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:ba8cbf57cfd92d5f8592b4aca1a35d92c162363d32aeabd5b12555f8896635e7\"\r\n  name = \"golang.org/x/sys\"\r\n  packages = [\r\n    \"unix\",\r\n    \"windows\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"4d1cda033e0619309c606fc686de3adcf599539e\"\r\n\r\n[[projects]]\r\n  digest = \"1:a2ab62866c75542dd18d2b069fec854577a20211d7c0ea6ae746072a1dccdd18\"\r\n  name = \"golang.org/x/text\"\r\n  packages = [\r\n    \"collate\",\r\n    \"collate/build\",\r\n    \"internal/colltab\",\r\n    \"internal/gen\",\r\n    \"internal/tag\",\r\n    \"internal/triegen\",\r\n    \"internal/ucd\",\r\n    \"language\",\r\n    \"secure/bidirule\",\r\n    \"transform\",\r\n    \"unicode/bidi\",\r\n    \"unicode/cldr\",\r\n    \"unicode/norm\",\r\n    \"unicode/rangetable\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"f21a4dfb5e38f5895301dc265a8def02365cc3d0\"\r\n  version = \"v0.3.0\"\r\n\r\n[[projects]]\r\n  branch = \"master\"\r\n  digest = \"1:077c1c599507b3b3e9156d17d36e1e61928ee9b53a5b420f10f28ebd4a0b275c\"\r\n  name = \"google.golang.org/genproto\"\r\n  packages = [\"googleapis/rpc/status\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"bd91e49a0898e27abb88c339b432fa53d7497ac0\"\r\n\r\n[[projects]]\r\n  digest = \"1:9edd250a3c46675d0679d87540b30c9ed253b19bd1fd1af08f4f5fb3c79fc487\"\r\n  name = \"google.golang.org/grpc\"\r\n  packages = [\r\n    \".\",\r\n    \"balancer\",\r\n    \"balancer/base\",\r\n    \"balancer/roundrobin\",\r\n    \"binarylog/grpc_binarylog_v1\",\r\n    \"codes\",\r\n    \"connectivity\",\r\n    \"credentials\",\r\n    \"credentials/internal\",\r\n    \"encoding\",\r\n    \"encoding/proto\",\r\n    \"grpclog\",\r\n    \"internal\",\r\n    \"internal/backoff\",\r\n    \"internal/binarylog\",\r\n    \"internal/channelz\",\r\n    \"internal/envconfig\",\r\n    \"internal/grpcrand\",\r\n    \"internal/grpcsync\",\r\n    \"internal/syscall\",\r\n    \"internal/transport\",\r\n    \"keepalive\",\r\n    \"metadata\",\r\n    \"naming\",\r\n    \"peer\",\r\n    \"resolver\",\r\n    \"resolver/dns\",\r\n    \"resolver/passthrough\",\r\n    \"stats\",\r\n    \"status\",\r\n    \"tap\",\r\n  ]\r\n  pruneopts = \"UT\"\r\n  revision = \"df014850f6dee74ba2fc94874043a9f3f75fbfd8\"\r\n  version = \"v1.17.0\"\r\n\r\n[[projects]]\r\n  digest = \"1:cbc72c4c4886a918d6ab4b95e347ffe259846260f99ebdd8a198c2331cf2b2e9\"\r\n  name = \"gopkg.in/go-playground/validator.v8\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"5f1438d3fca68893a817e4a66806cea46a9e4ebf\"\r\n  version = \"v8.18.2\"\r\n\r\n[[projects]]\r\n  digest = \"1:4d2e5a73dc1500038e504a8d78b986630e3626dc027bc030ba5c75da257cdb96\"\r\n  name = \"gopkg.in/yaml.v2\"\r\n  packages = [\".\"]\r\n  pruneopts = \"UT\"\r\n  revision = \"51d6538a90f86fe93ac480b35f37b2be17fef232\"\r\n  version = \"v2.2.2\"\r\n\r\n[solve-meta]\r\n  analyzer-name = \"dep\"\r\n  analyzer-version = 1\r\n  input-imports = [\r\n    \"github.com/asaskevich/EventBus\",\r\n    \"github.com/cloudevents/sdk-go/v02\",\r\n    \"github.com/gin-gonic/gin\",\r\n    \"github.com/golang/protobuf/proto\",\r\n    \"github.com/goph/emperror\",\r\n    \"github.com/goph/logur\",\r\n    \"github.com/karlseguin/ccache\",\r\n    \"github.com/patrickmn/go-cache\",\r\n    \"github.com/pkg/errors\",\r\n    \"github.com/satori/go.uuid\",\r\n    \"github.com/sirupsen/logrus\",\r\n    \"github.com/spf13/cast\",\r\n    \"github.com/spf13/pflag\",\r\n    \"github.com/spf13/viper\",\r\n    \"golang.org/x/net/context\",\r\n    \"google.golang.org/grpc\",\r\n    \"gopkg.in/go-playground/validator.v8\",\r\n    \"gopkg.in/yaml.v2\",\r\n  ]\r\n  solver-name = \"gps-cdcl\"\r\n  solver-version = 1"`

## ComposerLock (object)
+ contents: `{"_readme":["This file locks the dependencies of your project to a known state","Read more about it at https://getcomposer.org/doc/01-basic-usage.md#composer-lock-the-lock-file","This file is @generated automatically"],"content-hash":"3a3771e545494c4c098e639bd68602ba","packages":[{"name":"aws/aws-sdk-php","version":"3.0.0","source":{"type":"git","url":"https://github.com/aws/aws-sdk-php.git","reference":"4018c8f14a9e53003bb0417fa859c6a7ad57b53b"},"dist":{"type":"zip","url":"https://api.github.com/repos/aws/aws-sdk-php/zipball/4018c8f14a9e53003bb0417fa859c6a7ad57b53b","reference":"4018c8f14a9e53003bb0417fa859c6a7ad57b53b","shasum":""},"require":{"guzzlehttp/guzzle":"^5.3 || ^6.0.1","guzzlehttp/promises":"^1.0.0","guzzlehttp/psr7":"^1.0.0","mtdowling/jmespath.php":"^2.2","php":">=5.5"},"require-dev":{"ext-dom":"*","ext-json":"*","ext-openssl":"*","ext-pcre":"*","ext-simplexml":"*","ext-spl":"*","phpunit/phpunit":"^4.0"},"suggest":{"ext-curl":"To send requests using cURL","ext-openssl":"Allows working with CloudFront private distributions and verifying received SNS messages"},"type":"library","extra":{"branch-alias":{"dev-master":"3.0-dev"}},"autoload":{"psr-4":{"Aws\\":"src/"},"files":["src/functions.php"]},"notification-url":"https://packagist.org/downloads/","license":["Apache-2.0"],"authors":[{"name":"Amazon Web Services","homepage":"http://aws.amazon.com"}],"description":"AWS SDK for PHP - Use Amazon Web Services in your PHP project","homepage":"http://aws.amazon.com/sdkforphp","keywords":["amazon","aws","cloud","dynamodb","ec2","glacier","s3","sdk"],"time":"2015-05-27T20:07:42+00:00"},{"name":"doctrine/annotations","version":"v1.5.0","source":{"type":"git","url":"https://github.com/doctrine/annotations.git","reference":"5beebb01b025c94e93686b7a0ed3edae81fe3e7f"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/annotations/zipball/5beebb01b025c94e93686b7a0ed3edae81fe3e7f","reference":"5beebb01b025c94e93686b7a0ed3edae81fe3e7f","shasum":""},"require":{"doctrine/lexer":"1.*","php":"^7.1"},"require-dev":{"doctrine/cache":"1.*","phpunit/phpunit":"^5.7"},"type":"library","extra":{"branch-alias":{"dev-master":"1.5.x-dev"}},"autoload":{"psr-4":{"Doctrine\\Common\\Annotations\\":"lib/Doctrine/Common/Annotations"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Benjamin Eberlei","email":"kontakt@beberlei.de"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Jonathan Wage","email":"jonwage@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Docblock Annotations Parser","homepage":"http://www.doctrine-project.org","keywords":["annotations","docblock","parser"],"time":"2017-07-22T10:58:02+00:00"},{"name":"doctrine/cache","version":"v1.7.1","source":{"type":"git","url":"https://github.com/doctrine/cache.git","reference":"b3217d58609e9c8e661cd41357a54d926c4a2a1a"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/cache/zipball/b3217d58609e9c8e661cd41357a54d926c4a2a1a","reference":"b3217d58609e9c8e661cd41357a54d926c4a2a1a","shasum":""},"require":{"php":"~7.1"},"conflict":{"doctrine/common":">2.2,<2.4"},"require-dev":{"alcaeus/mongo-php-adapter":"^1.1","mongodb/mongodb":"^1.1","phpunit/phpunit":"^5.7","predis/predis":"~1.0"},"suggest":{"alcaeus/mongo-php-adapter":"Required to use legacy MongoDB driver"},"type":"library","extra":{"branch-alias":{"dev-master":"1.7.x-dev"}},"autoload":{"psr-4":{"Doctrine\\Common\\Cache\\":"lib/Doctrine/Common/Cache"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Benjamin Eberlei","email":"kontakt@beberlei.de"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Jonathan Wage","email":"jonwage@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Caching library offering an object-oriented API for many cache backends","homepage":"http://www.doctrine-project.org","keywords":["cache","caching"],"time":"2017-08-25T07:02:50+00:00"},{"name":"doctrine/collections","version":"v1.5.0","source":{"type":"git","url":"https://github.com/doctrine/collections.git","reference":"a01ee38fcd999f34d9bfbcee59dbda5105449cbf"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/collections/zipball/a01ee38fcd999f34d9bfbcee59dbda5105449cbf","reference":"a01ee38fcd999f34d9bfbcee59dbda5105449cbf","shasum":""},"require":{"php":"^7.1"},"require-dev":{"doctrine/coding-standard":"~0.1@dev","phpunit/phpunit":"^5.7"},"type":"library","extra":{"branch-alias":{"dev-master":"1.3.x-dev"}},"autoload":{"psr-0":{"Doctrine\\Common\\Collections\\":"lib/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Benjamin Eberlei","email":"kontakt@beberlei.de"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Jonathan Wage","email":"jonwage@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Collections Abstraction library","homepage":"http://www.doctrine-project.org","keywords":["array","collections","iterator"],"time":"2017-07-22T10:37:32+00:00"},{"name":"doctrine/common","version":"v2.5.0","source":{"type":"git","url":"https://github.com/doctrine/common.git","reference":"cd8daf2501e10c63dced7b8b9b905844316ae9d3"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/common/zipball/cd8daf2501e10c63dced7b8b9b905844316ae9d3","reference":"cd8daf2501e10c63dced7b8b9b905844316ae9d3","shasum":""},"require":{"doctrine/annotations":"1.*","doctrine/cache":"1.*","doctrine/collections":"1.*","doctrine/inflector":"1.*","doctrine/lexer":"1.*","php":">=5.3.2"},"require-dev":{"phpunit/phpunit":"~3.7"},"type":"library","extra":{"branch-alias":{"dev-master":"2.6.x-dev"}},"autoload":{"psr-0":{"Doctrine\\Common\\":"lib/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Benjamin Eberlei","email":"kontakt@beberlei.de"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Jonathan Wage","email":"jonwage@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Common Library for Doctrine projects","homepage":"http://www.doctrine-project.org","keywords":["annotations","collections","eventmanager","persistence","spl"],"time":"2015-04-02T19:55:44+00:00"},{"name":"doctrine/inflector","version":"v1.2.0","source":{"type":"git","url":"https://github.com/doctrine/inflector.git","reference":"e11d84c6e018beedd929cff5220969a3c6d1d462"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/inflector/zipball/e11d84c6e018beedd929cff5220969a3c6d1d462","reference":"e11d84c6e018beedd929cff5220969a3c6d1d462","shasum":""},"require":{"php":"^7.0"},"require-dev":{"phpunit/phpunit":"^6.2"},"type":"library","extra":{"branch-alias":{"dev-master":"1.2.x-dev"}},"autoload":{"psr-4":{"Doctrine\\Common\\Inflector\\":"lib/Doctrine/Common/Inflector"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Benjamin Eberlei","email":"kontakt@beberlei.de"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Jonathan Wage","email":"jonwage@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Common String Manipulations with regard to casing and singular/plural rules.","homepage":"http://www.doctrine-project.org","keywords":["inflection","pluralize","singularize","string"],"time":"2017-07-22T12:18:28+00:00"},{"name":"doctrine/lexer","version":"v1.0.1","source":{"type":"git","url":"https://github.com/doctrine/lexer.git","reference":"83893c552fd2045dd78aef794c31e694c37c0b8c"},"dist":{"type":"zip","url":"https://api.github.com/repos/doctrine/lexer/zipball/83893c552fd2045dd78aef794c31e694c37c0b8c","reference":"83893c552fd2045dd78aef794c31e694c37c0b8c","shasum":""},"require":{"php":">=5.3.2"},"type":"library","extra":{"branch-alias":{"dev-master":"1.0.x-dev"}},"autoload":{"psr-0":{"Doctrine\\Common\\Lexer\\":"lib/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Roman Borschel","email":"roman@code-factory.org"},{"name":"Guilherme Blanco","email":"guilhermeblanco@gmail.com"},{"name":"Johannes Schmitt","email":"schmittjoh@gmail.com"}],"description":"Base library for a lexer that can be used in Top-Down, Recursive Descent Parsers.","homepage":"http://www.doctrine-project.org","keywords":["lexer","parser"],"time":"2014-09-09T13:34:57+00:00"},{"name":"guzzlehttp/guzzle","version":"6.3.0","source":{"type":"git","url":"https://github.com/guzzle/guzzle.git","reference":"f4db5a78a5ea468d4831de7f0bf9d9415e348699"},"dist":{"type":"zip","url":"https://api.github.com/repos/guzzle/guzzle/zipball/f4db5a78a5ea468d4831de7f0bf9d9415e348699","reference":"f4db5a78a5ea468d4831de7f0bf9d9415e348699","shasum":""},"require":{"guzzlehttp/promises":"^1.0","guzzlehttp/psr7":"^1.4","php":">=5.5"},"require-dev":{"ext-curl":"*","phpunit/phpunit":"^4.0 || ^5.0","psr/log":"^1.0"},"suggest":{"psr/log":"Required for using the Log middleware"},"type":"library","extra":{"branch-alias":{"dev-master":"6.2-dev"}},"autoload":{"files":["src/functions_include.php"],"psr-4":{"GuzzleHttp\\":"src/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Michael Dowling","email":"mtdowling@gmail.com","homepage":"https://github.com/mtdowling"}],"description":"Guzzle is a PHP HTTP client library","homepage":"http://guzzlephp.org/","keywords":["client","curl","framework","http","http client","rest","web service"],"time":"2017-06-22T18:50:49+00:00"},{"name":"guzzlehttp/promises","version":"v1.3.1","source":{"type":"git","url":"https://github.com/guzzle/promises.git","reference":"a59da6cf61d80060647ff4d3eb2c03a2bc694646"},"dist":{"type":"zip","url":"https://api.github.com/repos/guzzle/promises/zipball/a59da6cf61d80060647ff4d3eb2c03a2bc694646","reference":"a59da6cf61d80060647ff4d3eb2c03a2bc694646","shasum":""},"require":{"php":">=5.5.0"},"require-dev":{"phpunit/phpunit":"^4.0"},"type":"library","extra":{"branch-alias":{"dev-master":"1.4-dev"}},"autoload":{"psr-4":{"GuzzleHttp\\Promise\\":"src/"},"files":["src/functions_include.php"]},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Michael Dowling","email":"mtdowling@gmail.com","homepage":"https://github.com/mtdowling"}],"description":"Guzzle promises library","keywords":["promise"],"time":"2016-12-20T10:07:11+00:00"},{"name":"guzzlehttp/psr7","version":"1.4.2","source":{"type":"git","url":"https://github.com/guzzle/psr7.git","reference":"f5b8a8512e2b58b0071a7280e39f14f72e05d87c"},"dist":{"type":"zip","url":"https://api.github.com/repos/guzzle/psr7/zipball/f5b8a8512e2b58b0071a7280e39f14f72e05d87c","reference":"f5b8a8512e2b58b0071a7280e39f14f72e05d87c","shasum":""},"require":{"php":">=5.4.0","psr/http-message":"~1.0"},"provide":{"psr/http-message-implementation":"1.0"},"require-dev":{"phpunit/phpunit":"~4.0"},"type":"library","extra":{"branch-alias":{"dev-master":"1.4-dev"}},"autoload":{"psr-4":{"GuzzleHttp\\Psr7\\":"src/"},"files":["src/functions_include.php"]},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Michael Dowling","email":"mtdowling@gmail.com","homepage":"https://github.com/mtdowling"},{"name":"Tobias Schultze","homepage":"https://github.com/Tobion"}],"description":"PSR-7 message implementation that also provides common utility methods","keywords":["http","message","request","response","stream","uri","url"],"time":"2017-03-20T17:10:46+00:00"},{"name":"mtdowling/jmespath.php","version":"2.4.0","source":{"type":"git","url":"https://github.com/jmespath/jmespath.php.git","reference":"adcc9531682cf87dfda21e1fd5d0e7a41d292fac"},"dist":{"type":"zip","url":"https://api.github.com/repos/jmespath/jmespath.php/zipball/adcc9531682cf87dfda21e1fd5d0e7a41d292fac","reference":"adcc9531682cf87dfda21e1fd5d0e7a41d292fac","shasum":""},"require":{"php":">=5.4.0"},"require-dev":{"phpunit/phpunit":"~4.0"},"bin":["bin/jp.php"],"type":"library","extra":{"branch-alias":{"dev-master":"2.0-dev"}},"autoload":{"psr-4":{"JmesPath\\":"src/"},"files":["src/JmesPath.php"]},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Michael Dowling","email":"mtdowling@gmail.com","homepage":"https://github.com/mtdowling"}],"description":"Declaratively specify how to extract elements from a JSON document","keywords":["json","jsonpath"],"time":"2016-12-03T22:08:25+00:00"},{"name":"psr/http-message","version":"1.0.1","source":{"type":"git","url":"https://github.com/php-fig/http-message.git","reference":"f6561bf28d520154e4b0ec72be95418abe6d9363"},"dist":{"type":"zip","url":"https://api.github.com/repos/php-fig/http-message/zipball/f6561bf28d520154e4b0ec72be95418abe6d9363","reference":"f6561bf28d520154e4b0ec72be95418abe6d9363","shasum":""},"require":{"php":">=5.3.0"},"type":"library","extra":{"branch-alias":{"dev-master":"1.0.x-dev"}},"autoload":{"psr-4":{"Psr\\Http\\Message\\":"src/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"PHP-FIG","homepage":"http://www.php-fig.org/"}],"description":"Common interface for HTTP messages","homepage":"https://github.com/php-fig/http-message","keywords":["http","http-message","psr","psr-7","request","response"],"time":"2016-08-06T14:39:51+00:00"},{"name":"psr/log","version":"1.0.2","source":{"type":"git","url":"https://github.com/php-fig/log.git","reference":"4ebe3a8bf773a19edfe0a84b6585ba3d401b724d"},"dist":{"type":"zip","url":"https://api.github.com/repos/php-fig/log/zipball/4ebe3a8bf773a19edfe0a84b6585ba3d401b724d","reference":"4ebe3a8bf773a19edfe0a84b6585ba3d401b724d","shasum":""},"require":{"php":">=5.3.0"},"type":"library","extra":{"branch-alias":{"dev-master":"1.0.x-dev"}},"autoload":{"psr-4":{"Psr\\Log\\":"Psr/Log/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"PHP-FIG","homepage":"http://www.php-fig.org/"}],"description":"Common interface for logging libraries","homepage":"https://github.com/php-fig/log","keywords":["log","psr","psr-3"],"time":"2016-10-10T12:19:37+00:00"},{"name":"symfony/icu","version":"v1.2.2","target-dir":"Symfony/Component/Icu","source":{"type":"git","url":"https://github.com/symfony/icu.git","reference":"d4d85d6055b87f394d941b45ddd3a9173e1e3d2a"},"dist":{"type":"zip","url":"https://api.github.com/repos/symfony/icu/zipball/d4d85d6055b87f394d941b45ddd3a9173e1e3d2a","reference":"d4d85d6055b87f394d941b45ddd3a9173e1e3d2a","shasum":""},"require":{"ext-intl":"*","lib-icu":">=4.4","php":">=5.3.3","symfony/intl":"~2.3"},"type":"library","autoload":{"psr-0":{"Symfony\\Component\\Icu\\":""}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Symfony Community","homepage":"http://symfony.com/contributors"},{"name":"Bernhard Schussek","email":"bschussek@gmail.com"}],"description":"Contains an excerpt of the ICU data and classes to load it.","homepage":"http://symfony.com","keywords":["icu","intl"],"abandoned":"symfony/intl","time":"2014-07-25T09:58:17+00:00"},{"name":"symfony/symfony","version":"v2.3.1","source":{"type":"git","url":"https://github.com/symfony/symfony.git","reference":"0902c606b4df1161f5b786ae89f37b71380b1f23"},"dist":{"type":"zip","url":"https://api.github.com/repos/symfony/symfony/zipball/0902c606b4df1161f5b786ae89f37b71380b1f23","reference":"0902c606b4df1161f5b786ae89f37b71380b1f23","shasum":""},"require":{"doctrine/common":"~2.2","php":">=5.3.3","psr/log":"~1.0","symfony/icu":"~1.0","twig/twig":"~1.11"},"replace":{"symfony/browser-kit":"self.version","symfony/class-loader":"self.version","symfony/config":"self.version","symfony/console":"self.version","symfony/css-selector":"self.version","symfony/debug":"self.version","symfony/dependency-injection":"self.version","symfony/doctrine-bridge":"self.version","symfony/dom-crawler":"self.version","symfony/event-dispatcher":"self.version","symfony/filesystem":"self.version","symfony/finder":"self.version","symfony/form":"self.version","symfony/framework-bundle":"self.version","symfony/http-foundation":"self.version","symfony/http-kernel":"self.version","symfony/intl":"self.version","symfony/locale":"self.version","symfony/monolog-bridge":"self.version","symfony/options-resolver":"self.version","symfony/process":"self.version","symfony/propel1-bridge":"self.version","symfony/property-access":"self.version","symfony/proxy-manager-bridge":"self.version","symfony/routing":"self.version","symfony/security":"self.version","symfony/security-bundle":"self.version","symfony/serializer":"self.version","symfony/stopwatch":"self.version","symfony/swiftmailer-bridge":"self.version","symfony/templating":"self.version","symfony/translation":"self.version","symfony/twig-bridge":"self.version","symfony/twig-bundle":"self.version","symfony/validator":"self.version","symfony/web-profiler-bundle":"self.version","symfony/yaml":"self.version"},"require-dev":{"doctrine/data-fixtures":"1.0.*","doctrine/dbal":"~2.2","doctrine/orm":"~2.2,>=2.2.3","ircmaxell/password-compat":"1.0.*","monolog/monolog":"~1.3","ocramius/proxy-manager":">=0.3.1,<0.4-dev","propel/propel1":"1.6.*"},"type":"library","extra":{"branch-alias":{"dev-master":"2.3-dev"}},"autoload":{"psr-0":{"Symfony\\":"src/"},"classmap":["src/Symfony/Component/HttpFoundation/Resources/stubs","src/Symfony/Component/Intl/Resources/stubs"],"files":["src/Symfony/Component/Intl/Resources/stubs/functions.php"]},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Symfony Community","homepage":"http://symfony.com/contributors"},{"name":"Fabien Potencier","email":"fabien@symfony.com"}],"description":"The Symfony PHP framework","homepage":"http://symfony.com","keywords":["framework"],"time":"2013-06-11T11:46:38+00:00"},{"name":"twig/twig","version":"v1.35.0","source":{"type":"git","url":"https://github.com/twigphp/Twig.git","reference":"daa657073e55b0a78cce8fdd22682fddecc6385f"},"dist":{"type":"zip","url":"https://api.github.com/repos/twigphp/Twig/zipball/daa657073e55b0a78cce8fdd22682fddecc6385f","reference":"daa657073e55b0a78cce8fdd22682fddecc6385f","shasum":""},"require":{"php":">=5.3.3"},"require-dev":{"psr/container":"^1.0","symfony/debug":"~2.7","symfony/phpunit-bridge":"~3.3@dev"},"type":"library","extra":{"branch-alias":{"dev-master":"1.35-dev"}},"autoload":{"psr-0":{"Twig_":"lib/"},"psr-4":{"Twig\\":"src/"}},"notification-url":"https://packagist.org/downloads/","license":["BSD-3-Clause"],"authors":[{"name":"Fabien Potencier","email":"fabien@symfony.com","homepage":"http://fabien.potencier.org","role":"Lead Developer"},{"name":"Armin Ronacher","email":"armin.ronacher@active-4.com","role":"Project Founder"},{"name":"Twig Team","homepage":"http://twig.sensiolabs.org/contributors","role":"Contributors"}],"description":"Twig, the flexible, fast, and secure template language for PHP","homepage":"http://twig.sensiolabs.org","keywords":["templating"],"time":"2017-09-27T18:06:46+00:00"},{"name":"yiisoft/yii","version":"1.1.14","source":{"type":"git","url":"https://github.com/yiisoft/yii.git","reference":"f0fee98ee84f70f1f3652f65562c9670e919cb4e"},"dist":{"type":"zip","url":"https://api.github.com/repos/yiisoft/yii/zipball/f0fee98ee84f70f1f3652f65562c9670e919cb4e","reference":"f0fee98ee84f70f1f3652f65562c9670e919cb4e","shasum":""},"require":{"php":">=5.1.0"},"bin":["framework/yiic"],"type":"library","notification-url":"https://packagist.org/downloads/","license":["BSD-3-Clause"],"authors":[{"name":"Qiang Xue","email":"qiang.xue@gmail.com","homepage":"http://www.yiiframework.com/","role":"Founder and project lead"},{"name":"Alexander Makarov","email":"sam@rmcreative.ru","homepage":"http://rmcreative.ru/","role":"Core framework development"},{"name":"Maurizio Domba","homepage":"http://mdomba.info/","role":"Core framework development"},{"name":"Carsten Brandt","email":"mail@cebe.cc","homepage":"http://cebe.cc/","role":"Core framework development"},{"name":"Wei Zhuo","email":"weizhuo@gmail.com","role":"Project site maintenance and development"},{"name":"Sebastián Thierer","email":"sebas@artfos.com","role":"Component development"},{"name":"Jeffrey Winesett","email":"jefftulsa@gmail.com","role":"Documentation and marketing"},{"name":"Timur Ruziev","email":"resurtm@gmail.com","homepage":"http://resurtm.com/","role":"Core framework development"},{"name":"Paul Klimov","email":"klimov.paul@gmail.com","role":"Core framework development"}],"description":"Yii Web Programming Framework","homepage":"http://www.yiiframework.com/","keywords":["framework","yii"],"time":"2013-08-12T00:12:08+00:00"},{"name":"zendframework/zendframework","version":"2.1.0","source":{"type":"git","url":"https://github.com/zendframework/zendframework.git","reference":"345a8cbedbe8de8a25bf18579fe54d169ac5075a"},"dist":{"type":"zip","url":"https://api.github.com/repos/zendframework/zendframework/zipball/345a8cbedbe8de8a25bf18579fe54d169ac5075a","reference":"345a8cbedbe8de8a25bf18579fe54d169ac5075a","shasum":""},"require":{"php":">=5.3.3"},"replace":{"zendframework/zend-authentication":"self.version","zendframework/zend-barcode":"self.version","zendframework/zend-cache":"self.version","zendframework/zend-captcha":"self.version","zendframework/zend-code":"self.version","zendframework/zend-config":"self.version","zendframework/zend-console":"self.version","zendframework/zend-crypt":"self.version","zendframework/zend-db":"self.version","zendframework/zend-debug":"self.version","zendframework/zend-di":"self.version","zendframework/zend-dom":"self.version","zendframework/zend-escaper":"self.version","zendframework/zend-eventmanager":"self.version","zendframework/zend-feed":"self.version","zendframework/zend-file":"self.version","zendframework/zend-filter":"self.version","zendframework/zend-form":"self.version","zendframework/zend-http":"self.version","zendframework/zend-i18n":"self.version","zendframework/zend-inputfilter":"self.version","zendframework/zend-json":"self.version","zendframework/zend-ldap":"self.version","zendframework/zend-loader":"self.version","zendframework/zend-log":"self.version","zendframework/zend-mail":"self.version","zendframework/zend-math":"self.version","zendframework/zend-memory":"self.version","zendframework/zend-mime":"self.version","zendframework/zend-modulemanager":"self.version","zendframework/zend-mvc":"self.version","zendframework/zend-navigation":"self.version","zendframework/zend-paginator":"self.version","zendframework/zend-permissions-acl":"self.version","zendframework/zend-permissions-rbac":"self.version","zendframework/zend-progressbar":"self.version","zendframework/zend-serializer":"self.version","zendframework/zend-server":"self.version","zendframework/zend-servicemanager":"self.version","zendframework/zend-session":"self.version","zendframework/zend-soap":"self.version","zendframework/zend-stdlib":"self.version","zendframework/zend-tag":"self.version","zendframework/zend-test":"self.version","zendframework/zend-text":"self.version","zendframework/zend-uri":"self.version","zendframework/zend-validator":"self.version","zendframework/zend-version":"self.version","zendframework/zend-view":"self.version","zendframework/zend-xmlrpc":"self.version"},"require-dev":{"doctrine/common":">=2.1","phpunit/phpunit":"3.7.*"},"suggest":{"doctrine/common":"Doctrine\\Common >=2.1 for annotation features","ext-intl":"ext/intl for i18n features","pecl-weakref":"Implementation of weak references for Zend\\Stdlib\\CallbackHandler","zendframework/zendpdf":"ZendPdf for creating PDF representations of barcodes","zendframework/zendservice-recaptcha":"ZendService\\ReCaptcha for rendering ReCaptchas in Zend\\Captcha and/or Zend\\Form"},"bin":["bin/classmap_generator.php"],"type":"library","extra":{"branch-alias":{"dev-master":"2.1-dev","dev-develop":"2.2-dev"}},"autoload":{"psr-0":{"Zend\\":"library/","ZendTest\\":"tests/"}},"notification-url":"https://packagist.org/downloads/","license":["BSD-3-Clause"],"description":"Zend Framework 2","homepage":"http://framework.zend.com/","keywords":["framework","zf2"],"time":"2013-01-30T16:46:21+00:00"}],"packages-dev":[],"aliases":[],"minimum-stability":"stable","stability-flags":[],"prefer-stable":false,"prefer-lowest":false,"platform":{"php":">=5.3.2"},"platform-dev":[]}`

## DepGraphData (object)
+ schemaVersion (string, required) - Snyk DepGraph library schema version.
+ pkgManager (PkgManager, required) - Package manager information.
+ pkgs (array[Package], required) - Array of package dependencies.
+ graph (Graph, required) - Graph object references each pkg and how they depend on each other through the deps property.

## PkgManager (object)
+ name (string, required) - Package manager name.
+ repositories (array[Repository]) - A list of package repositories (i.e. maven-central, or npm) that defaults to the canonical package registry for the given package manager.

## Repository (object)
+ alias (string) - deb, apk and rpm package managers should use an alias to indicate the target Operating System, for example 'debian:10'.

## Package (object)
+ id (string, required) - Unique package identifier, should take the format name@version.
+ info (PackageInfo, required) - Package name and version.

## PackageInfo (object)
+ name (string, required) - Package name.
+ version (string, required) - Package version.

## Graph (object)
+ rootNodeId (string, required) - Root node id.
+ nodes (array[Node], required) - Array of node objects.

## Node (object)
+ nodeId (string, required) - Node id unique across the graph.
+ pkgId (string, required) - Package id reference should match id in pkg array and take the format name@version.
+ deps (array[GraphDependency]) - An array of package ids this package depends on.

## GraphDependency (object)
+ nodeId (string, required) - Node id unique across the graph.
# Group Monitor
Snyk constantly discloses new vulnerabilities. Monitor gives you a way to regularly test your project for
new vulnerabilities and be alerted when action is required in order to keep your project secure.

## DepGraph [/monitor/dep-graph]
Experimental! Note these endpoints are subject to change and only available to selected users. Please
contact [support@snyk.io](mailto:support@snyk.io) to request access.

The following package managers are supported:

* deb
* gomodules
* gradle
* maven
* nuget
* paket
* pip
* rpm
* rubygems
* cocoapods
* npm
* yarn

The name of the root node in the dep-graph is used as the project name when creating a project. This should
be unique for your organization. In the example given below 'my-maven-app' will be the project name.

To inform Snyk that some dependencies in your project have changed ensure subsequent requests use the same root node
name.

### Monitor Dep Graph [POST /monitor/dep-graph{?org}]
Use this endpoint to monitor a [DepGraph data object](https://github.com/snyk/dep-graph#depgraphdata).

+ Parameters
    + org: `9695cbb1-3a87-4d6f-8ae1-61a1c37ee9f7` (string, optional) - The organization to test the package with. See "The Snyk organization for a request" above.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `Add Project`
        + `Test Project`

    + Headers

            Authorization: token API_KEY

    + Attributes (monitor graph payload)

    + Body

            {
              "depGraph": {
                "schemaVersion": "1.2.0",
                "pkgManager": {
                  "name": "maven"
                },
                "pkgs": [
                  {
                    "id": "my-maven-app@1.0.0",
                    "info": {
                      "name": "my-maven-app",
                      "version": "1.0.0"
                    }
                  },
                  {
                    "id": "ch.qos.logback:logback-core@1.0.13",
                    "info": {
                      "name": "ch.qos.logback:logback-core",
                      "version": "1.0.13"
                    }
                  }
                ],
                "graph": {
                  "rootNodeId": "root-node",
                  "nodes": [
                    {
                      "nodeId": "root-node",
                      "pkgId": "my-maven-app@1.0.0",
                      "deps": [
                        {
                          "nodeId": "ch.qos.logback:logback-core@1.0.13"
                        }
                      ]
                    },
                    {
                      "nodeId": "ch.qos.logback:logback-core@1.0.13",
                      "pkgId": "ch.qos.logback:logback-core@1.0.13",
                      "deps": []
                    }
                  ]
                }
              }
            }


+ Response 200 (application/json; charset=utf-8)

        {
          "ok": true,
          "id": "f7c065cd-5850-462d-a0ca-9719d07e3e38",
          "uri": "https://app.snyk.io/org/my-org/project/f7c065cd-5850-462d-a0ca-9719d07e3e38/history/39d14036-31f3-4f22-8037-1d979e0516ef"
        }

# Data Structures

## monitor graph payload
+ depGraph (MonitorDepGraphData, required) - A [DepGraph data object](https://github.com/snyk/dep-graph#depgraphdata) defining all packages and their relationships.
+ meta (MonitorMetaData) - Project metadata

## MonitorDepGraphData (object)
+ schemaVersion (string, required) - Snyk DepGraph library schema version.
+ pkgManager (MonitorPkgManager, required) - Package manager information.
+ pkgs (array[MonitorPackage], required) - Array of package dependencies.
+ graph (MonitorGraph, required) - Graph object references each pkg and how they depend on each other through the deps property.

## MonitorMetaData (object)
+ targetFramework (string) - Required for a NuGet or Paket DepGraph only. Specify the target framework in your project file using Target Framework Monikers (TFMs). For example, netstandard1.0, netcoreapp1.0 or net452. Test each framework separately if you have multiple defined.

## MonitorPkgManager (object)
+ name (string, required) - Package manager name.
+ repositories (array[MonitorRepository]) - A list of package repositories (i.e. maven-central, or npm) that defaults to the canonical package registry for the given package manager.

## MonitorRepository (object)
+ alias (string) - deb, apk and rpm package managers should use an alias to indicate the target Operating System, for example 'debian:10'.

## MonitorPackage (object)
+ id (string, required) - Unique package identifier, should take the format name@version.
+ info (MonitorPackageInfo, required) - Package name and version.

## MonitorPackageInfo (object)
+ name (string, required) - Package name.
+ version (string, required) - Package version.

## MonitorGraph (object)
+ rootNodeId (string, required) - Root node id. Note the root node name is used as your project name.
+ nodes (array[MonitorNode], required) - Array of node objects.

## MonitorNode (object)
+ nodeId (string, required) - Node id unique across the graph.
+ pkgId (string, required) - Package id reference should match id in pkg array and take the format name@version.
+ deps (array[MonitorGraphDependency]) - An array of package ids this package depends on.

## MonitorGraphDependency (object)
+ nodeId (string, required) - Node id unique across the graph.
# Group Reporting API

Note: The endpoints in this category only support Snyk legacy reporting, not the latest release. As such, they are not available on MT-EU/AU and you can instead use [the Issues REST API](https://apidocs.snyk.io/#tag--Issues).

The reporting API powers our reports section. 

With it you can find answers to questions like how many issues your organisation has, or how many tests have been conducted in a given time frame.

Current rate limit is up to 70 requests per minute, per user.
All requests above the limit will get a response with status code `429` - `Too many requests` until requests stop for the duration of the rate-limiting interval (currently a minute).
For more information about rate-limiting see: [https://snyk.docs.apiary.io/#introduction/rate-limiting](https://snyk.docs.apiary.io/#introduction/rate-limiting)

## Latest Issues [/reporting/issues/latest{?page,perPage,sortBy,order,groupBy}]

Returns issues currently in existence. This data can take up to 9 hours to refresh.

+ Parameters
    + page: `1` (number, optional) - The page of results to request
    + perPage: `100` (number, optional) - The number of results to return per page (Maximum: 1000)
    + sortBy: `issueTitle` (enum[string], optional) - The key to sort results by
        + Members
            + `severity` - Sort by the severity of the issue (in the order low, medium, high, critical)
            + `issueTitle` - Sort alphabetically by the issue title
            + `projectName` - Sort alphabetically by the project name
            + `isFixed` - Sort by whether the issue has been fixed
            + `isPatched` - Sort by whether the issue has been patched
            + `isIgnored` - Sort by whether the issue has been ignored
            + `introducedDate` - Sort chronologically by the date that the issue was introduced into the project
            + `isUpgradable` - Sort by whether the issue can be fixed by upgrading to a later version of the dependency
            + `isPatchable` - Sort by whether the issue can be patched
            + `priorityScore` - Sort the issues by their priority score, highest to lowest.
    + order: `asc` (string, optional) - The direction to sort results.
    + groupBy: `issue` (enum[string], optional) - Set to issue to group the same issue in multiple projects
        + Members
            + `issue`

### Get list of latest issues [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Issues Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issues)

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Issues [/reporting/issues/{?from,to,page,perPage,sortBy,order,groupBy}]

Returns any issues that are present during the specified timeframe. For example, if an issue from 2018 is still considered a vulnerable today, it will show up in all reports from its inception to the current day. This data updates once per hour.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-07` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`
    + page: `1` (number, optional) - The page of results to request
    + perPage: `100` (number, optional) - The number of results to return per page (Maximum: 1000)
    + sortBy: `issueTitle` (enum[string], optional) - The key to sort results by
        + Members
            + `severity` - Sort by the severity of the issue (in the order low, medium, high, critical)
            + `issueTitle` - Sort alphabetically by the issue title
            + `projectName` - Sort alphabetically by the project name
            + `isFixed` - Sort by whether the issue has been fixed
            + `isPatched` - Sort by whether the issue has been patched
            + `isIgnored` - Sort by whether the issue has been ignored
            + `introducedDate` - Sort chronologically by the date that the issue was introduced into the project
            + `isUpgradable` - Sort by whether the issue can be fixed by upgrading to a later version of the dependency
            + `isPatchable` - Sort by whether the issue can be patched
            + `priorityScore` - Sort the issues by their priority score, highest to lowest.
    + order: `asc` (string, optional) - The direction to sort results.
    + groupBy: `issue` (enum[string], optional) - Set to issue to group the same issue in multiple projects
        + Members
            + `issue`

### Get list of issues [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Issues Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issues)

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Latest issue counts [/reporting/counts/issues/latest{?groupBy}]

Returns the number of issues currently in existence. This data can take up to 9 hours to refresh.

+ Parameters
    + groupBy: `severity` (enum[string], optional) - The field to group results by
        + Members
            + `severity`
            + `fixable`
            + `project,[severity|fixable]`

### Get latest issue counts [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Issue Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issue Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0,
                        "severity": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        },
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Issue counts over time [/reporting/counts/issues{?from,to,groupBy}]

Returns issue counts within a time frame. This data can take up to 9 hours to refresh.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`
    + groupBy: `severity` (enum[string], optional) - The field to group results by
        + Members
            + `severity`
            + `fixable`
            + `project,[severity|fixable]`

### Get issue counts [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Issue Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Issue Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0,
                        "severity": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    },
                    {
                        "day": "2017-07-02",
                        "count": 0,
                        "severity": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    },
                    {
                        "day": "2017-07-03",
                        "count": 0,
                        "severity": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "types": ["unsupported-type"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.types is an invalid type unsupported-type"
                    ]
                }
            }

## Latest project counts [/reporting/counts/projects/latest]

Returns the number of projects currently in existence. This data can take up to 9 hours to refresh.

+ Params

### Get latest project counts [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Project Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Project Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "projects": ["unsupported-project"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.projects is an invalid project unsupported-project"
                    ]
                }
            }

## Project counts over time [/reporting/counts/projects{?from,to}]

Returns project counts within a time frame. This data can take up to 9 hours to refresh.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to fetch results from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to fetch results until, in the format `YYYY-MM-DD`

### Get project counts [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Project Counts Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Project Counts)

    + Body

            {
                "results": [
                    {
                        "day": "2017-07-01",
                        "count": 0
                    },
                    {
                        "day": "2017-07-02",
                        "count": 0
                    },
                    {
                        "day": "2017-07-03",
                        "count": 0
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "projects": ["unsupported-project"]
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.projects is an invalid project unsupported-project"
                    ]
                }
            }

## Test counts [/reporting/counts/tests{?from,to,groupBy}]

Returns the number of tests conducted within a time frame. This data is updated in real time.

+ Parameters
    + from: `2017-07-01` (string) - The date you wish to count tests from, in the format `YYYY-MM-DD`
    + to: `2017-07-03` (string) - The date you wish to count tests until, in the format `YYYY-MM-DD`
    + groupBy: `isPrivate` (enum[string], optional) - The field to group results by
        + Members
            + `isPrivate`
            + `issuesPrevented`

### Get test counts [POST]

+ Request (application/json)
    + Required permissions
        + `View Project` for every Organization in `filters.orgs`
        + `View Organization Reports` for every Organization in `filters.orgs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Tests Filters)

+ Response 200 (application/json; charset=utf-8)

    + Attributes (Test Counts)

    + Body

            {
                "results": [
                    {
                        "count": 0,
                        "isPrivate": {
                            "true": 0,
                            "false": 0
                        }
                    }
                ]
            }

+ Request Invalid filters (application/json)
    + Headers

            Authorization: token API_KEY

    + Body

            {
                "filters": {
                    "isPrivate": "non-boolean-value"
                }
            }

+ Response 400 (application/json; charset=utf-8)

    + Attributes (Error Response)

    + Body

            {
                "code": 400,
                "ok": false,
                "error": {
                    "name": "ValidationError",
                    "innerErrors": [
                        "invalid type filters.isPrivate is not a Boolean"
                    ]
                }
            }

# Data Structures
# PriorityScore
+ min: 0 (optional, number)
+ max: 1000 (optional, number)

## Issues Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + severity (array) - The severity levels of issues to filter the results by
        + critical (string) - Include issues which are critical severity
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + exploitMaturity (array) - The exploit maturity levels of issues to filter the results by
        + mature (string) - Include issues which a published code exploit can easily be used for
        + `proof-of-concept` (string) - Include issues for which a published, theoretical proof-of-concept or detailed explanation that demonstrates how to exploit this vulnerability is available
        + `no-known-exploit` (string) - Include issues for which neither a proof-of-concept code nor an exploit were found for
        + `no-data` (string) - Include issues with no exploit maturity details: licenses, historic vulnerabilities, unsupported ecosystems or projects that require a re-scan
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
        + configuration (string) - Include configuration issues
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + javascript (string) - Include issues which are for JavaScript projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip or poetry)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep, govendor or gomodules)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget, paket)
        + `swift-objective-c` (string) - Include issues which are for Swift/Cocoapods projects (cocoapods)
        + elixir (string) - Include issues which are for Elixir/Erlang projects (hex)
        + docker (string) - Include issues which are for docker projects (apk, deb, rpm)
        + linux (string) - Include issues which are for Linux distros in docker projects (apk, deb, rpm)
        + dockerfile (string) - Include issues which are for docker projects (dockerfile)
        + terraform (string) - Include issues which are for Terraform projects (terraformconfig)
        + kubernetes (string) - Include issues which are for Kubernetes projects (k8smconfig)
        + helm (string) - Include issues which are for Helm projects (helmconfig)
        + cloudformation (string) - Include issues which are for CloudFormation projects (cloudformationconfig)
        + arm (string) - Include issues which are for ARM projects (armconfig)
    + projects (array) - The list of project IDs to filter issues by, max projects allowed is 1000
    + issues (array) - The list of issue IDs to filter issues by
    + identifier (string) - Search term to filter issue name by, or an exact CVE or CWE
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched
    + fixable (boolean) - If set to `true`, only include issues which are fixable, if set to `false`, only include issues which are not fixable. An issue is fixable if it is either upgradable, patchable or pinnable. Also see isUpgradable, isPatchable and isPinnable filters.
    + isFixed (boolean) - If set to `true`, only include issues which are fixed, if set to `false`, only include issues which are not fixed
    + isUpgradable (boolean) - If set to `true`, only include issues which are upgradable, if set to `false`, only include issues which are not upgradable
    + isPatchable (boolean) - If set to `true`, only include issues which are patchable, if set to `false`, only include issues which are not patchable
    + isPinnable (boolean) - If set to `true`, only include issues which are pinnable, if set to `false`, only include issues which are not pinnable
    + priorityScore (PriorityScore) - The priority score ranging between 0-1000

## Issue Counts Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + severity (array) - The severity levels of issues to filter the results by
        + critical (string) - Include issues which are critical severity
        + high (string) - Include issues which are high severity
        + medium (string) - Include issues which are medium severity
        + low (string) - Include issues which are low severity
    + types (array) - The type of issues to filter the results by
        + vuln (string) - Include issues which are vulnerabilities
        + license (string) - Include issues which are licenses
        + configuration (string) - Include configuration issues
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + javascript (string) - Include issues which are for JavaScript projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip or poetry)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep, govendor or gomodules)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget, paket)
        + `swift-objective-c` (string) - Include issues which are for Swift/Cocoapods projects (cocoapods)
        + elixir (string) - Include issues which are for Elixir/Erlang projects (hex)
        + docker (string) - Include issues which are for docker projects (apk, deb, rpm)
        + linux (string) - Include issues which are for Linux distros in docker projects (apk, deb, rpm)
        + dockerfile (string) - Include issues which are for docker projects (dockerfile)
        + terraform (string) - Include issues which are for Terraform projects (terraformconfig)
        + kubernetes (string) - Include issues which are for Kubernetes projects (k8smconfig)
        + helm (string) - Include issues which are for Helm projects (helmconfig)
        + cloudformation (string) - Include issues which are for CloudFormation projects (cloudformationconfig)
    + projects (array) - The list of project IDs to filter issues by, max projects allowed is 1000
    + ignored (boolean) - If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
    + patched (boolean) - If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched
    + fixable (boolean) - If set to `true`, only include issues which are fixable, if set to `false`, only include issues which are not fixable. An issue is fixable if it is either upgradable, patchable or pinnable. Also see isUpgradable, isPatchable and isPinnable filters.
    + isUpgradable (boolean) - If set to `true`, only include issues which are upgradable, if set to `false`, only include issues which are not upgradable
    + isPatchable (boolean) - If set to `true`, only include issues which are patchable, if set to `false`, only include issues which are not patchable
    + isPinnable (boolean) - If set to `true`, only include issues which are pinnable, if set to `false`, only include issues which are not pinnable
    + priorityScore (PriorityScore) - The priority score ranging between 0-1000

## Project Counts Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + languages (array) - The type of languages to filter the results by
        + node (string) - Include issues which are for NodeJS projects (npm or yarn package managers)
        + javascript (string) - Include issues which are for JavaScript projects (npm or yarn package managers)
        + ruby (string) - Include issues which are for Ruby projects (rubygems package manager)
        + java (string) - Include issues which are for Java projects (maven or gradle)
        + scala (string) - Include issues which are for Scala projects (sbt)
        + python (string) - Include issues which are for Python projects (pip or poetry)
        + golang (string) - Include issues which are for Golang projects (golang, golangdep, govendor or gomodules)
        + php (string) - Include issues which are for PHP projects (composer)
        + dotnet (string) - Include issues which are for .Net projects (nuget, paket)
        + `swift-objective-c` (string) - Include issues which are for Swift/Cocoapods projects (cocoapods)
        + elixir (string) - Include issues which are for Elixir/Erlang projects (hex)
        + docker (string) - Include issues which are for docker projects (apk, deb, rpm)
        + linux (string) - Include issues which are for Linux distros in docker projects (apk, deb, rpm)
        + dockerfile (string) - Include issues which are for docker projects (dockerfile)
        + terraform (string) - Include issues which are for Terraform projects (terraformconfig)
        + kubernetes (string) - Include issues which are for Kubernetes projects (k8smconfig)
        + helm (string) - Include issues which are for Helm projects (helmconfig)
        + cloudformation (string) - Include issues which are for CloudFormation projects (cloudformationconfig)
    + projects (array) - The list of project IDs to filter the results by, max projects allowed is 1000

## Tests Filters (object)

+ filters (object)
    + orgs (array, required) - The list of org IDs to filter the results by
    + isPrivate (boolean) - If set to `true`, only include tests which were conducted against private projects, if set to `false` only include tests which were conducted against public projects
    + issuesPrevented (boolean) - If set to `true`, only include tests which prevented issues from being introduced, if set to `false` only include tests which did not prevent issues from being introduced
    + projects (array) - The list of project IDs to filter issues by, max projects allowed is 1000

## Issues (object)

+ results (array, fixed-type, required) - A list of issues
    + (object, required)
        + issue (object, required)
            + url (string, required) - URL to a page containing information about the issue
            + id (string, required) - The identifier of the issue
            + title (string, required) - The issue title
            + type (string, required) - The issue type, can be "vuln", "license"
            + package (string, required) - The name of the package that the issue relates to
            + version (string, required) - The version of the package that the issue relates to
            + severity (string, required) - The severity status of the issue, after policies are applied
            + originalSeverity (string, required) - The original severity status of the issue, as retrieved from Snyk Vulnerability database, before policies are applied
            + uniqueSeveritiesList (array[string]) - A list of all severities in issue per projects
            + exploitMaturity (string, required) - The exploit maturity of the issue
            + isUpgradable (boolean) - Whether the issue can be fixed by upgrading to a later version of the dependency
            + isPatchable (boolean) - Whether the issue can be patched
            + isPinnable (boolean) - Whether the issue can be pinned
            + jiraIssueUrl (string) - The link to the Jira issue attached to the vulnerability
            + publicationTime (string) - The date that the vulnerability was first published by Snyk (not applicable to licenses)
            + disclosureTime (string) - The date that the vulnerability was first disclosed (not applicable to licenses)
            + language (string) - The language of the issue
            + packageManager (string) - The package manager of the issue
            + identifiers (object) - External identifiers assigned to the issue (not applicable to licenses)
                + CVE (array[string]) - Common Vulnerability Enumeration identifiers
                + CWE (array[string]) - Common Weakness Enumeration identifiers
                + OSVDB (array[string]) - Identifiers assigned by the Open Source Vulnerability Database (OSVDB)
            + credit (array[string]) - The list of people responsible for first uncovering or reporting the issue (not applicable to licenses)
            + CVSSv3 (string) - The CVSS v3 string that signifies how the CVSS score was calculated (not applicable to licenses)
            + priorityScore(number) - The priority score ranging between 0-1000
            + cvssScore (number) - The CVSS score that results from running the CVSSv3 string (not applicable to licenses)
            + patches (array) - A list of patches available for the given issue (not applicable to licenses)
                + (object)
                    + id (string) - The identifier of the patch
                    + urls (array[string]) - The URLs where the patch files can be downloaded
                    + version (string) - The version number(s) that the patch can be applied to
                    + comments (array[string]) - Any comments about the patch
                    + modificationTime (string) - When the patch was last modified
            + isIgnored (boolean) - Whether the issue has been ignored (only present if there is no `groupBy` in the API request)
            + isPatched (boolean) - Whether the issue has been patched (not applicable to licenses and only present if there is no `groupBy` in the API request)
            + semver (object) - The ranges that are vulnerable and unaffected by the issue
                + vulnerable (array[string]) - The ranges that are vulnerable to the issue
                + unaffected (string) - The ranges that are unaffected by the issue
            + ignored (array) - The list of ignore rules that were applied to the issue (only present if issue was ignored and no `groupBy` in the API request)
                + (object)
                    + reason (string) - A reason why the issue was ignored
                    + expires (string) - The date when the ignore will no longer apply
                    + source (enum[string]) - The place where the ignore rule was applied from
                        + Members
                            + `cli` - The ignore was applied via the CLI or filesystem
                            + `api` - The ignore was applied via the API or website
        + One of
            + projects (array, required) - When `groupBy` is used, multiple projects may be returned per issue
                + (object, required)
                    + url (string, required) - URL to a page containing information about the project
                    + id (string, required) - The identifier of the project
                    + name (string, required) - The name of the project
                    + source (string, required) - The source of the project (e.g. github, heroku etc)
                    + packageManager (string, required) - The package manager for the project (e.g. npm, rubygems etc)
                    + targetFile (string) - The file path to the dependency manifest or lock file (e.g. package.json, Gemfile.lock etc)
            + project (object, required) - When no `groupBy` is used, a single project is returned per issue
                + url (string, required) - URL to a page containing information about the project
                + id (string, required) - The identifier of the project
                + name (string, required) - The name of the project
                + source (string, required) - The source of the project (e.g. github, heroku etc)
                + packageManager (string, required) - The package manager for the project (e.g. npm, rubygems etc)
                + targetFile (string) - The file path to the dependency manifest or lock file (e.g. package.json, Gemfile.lock etc)

        + isFixed (boolean, required) - Whether the issue has been fixed
        + introducedDate (string, required) - The date that the issue was introduced into the project
        + patchedDate (string) - The date that the issue was patched
        + fixedDate (string) - The date that the issue was fixed
+ total (number, required) - The total number of results found

## Issue Counts (object)

+ results (array, fixed-type, required) - A list of issue counts by day
    + (object, required)
        + day (string, required) - The date in the format `YYYY-MM-DD`
        + count (number, required) - The number of issues
        + severity (object)
            + critical (number) - The number of critical severity issues
            + high (number) - The number of high severity issues
            + medium (number) - The number of medium severity issues
            + low (number) - The number of low severity issues
        + fixable (object)
            + true (number) - The number of fixable issues
            + false (number) - The number of non-fixable issues

## Project Counts (object)

+ results (array, fixed-type, required) - A list of project counts by day
    + (object, required)
        + day (string, required) - The date in the format `YYYY-MM-DD`
        + count (number, required) - The number of projects

## Test Counts (object)

+ results (array, fixed-type, required) - A list of test counts
    + (object, required)
        + count (number, required) - The number of tests conducted
        + isPrivate (object)
            + true (number) - The number of tests conducted against private projects
            + false (number) - The number of tests conducted against public projects
        + issuesPrevented (object)
            + true (number) - The number of tests that prevented issues from being introduced
            + false (number) - The number of tests that did not prevent issues from being introduced

## Error Response (object)

+ code: 400 (number, required) - The error response code
+ ok (boolean, required)
+ error (object, required)
    + name (string, required) - A descriptive message of the error
    + innerErrors (array[string]) - A list of additional reasons why the error occurred
# Group Audit logs
Get audit logs of your group or organization. Logs are only available for past 3 months. Note that the API returns personally identifiable information and requires the use of either a personal Snyk API token or a Snyk service account token with Group Admin level permission.

## Group level audit logs [/group/{groupId}/audit{?from,to,page,sortOrder}]
+ Parameters
    + groupId: `4a18d42f-0706-4ad0-b127-24078731fbea` (string, required) - The group ID. The `API_KEY` must have access to this group.
    + from: `2019-07-01` (string, optional) - The date you wish to fetch results from, in the format YYYY-MM-DD. Default is 3 months ago. Please note that logs are only available for past 3 months.
    + to: `2019-07-07` (string, optional) - The date you wish to fetch results until, in the format YYYY-MM-DD. Default is today. Please note that logs are only available for past 3 months.
    + page: `1` (number, optional) - The page of results to request. Audit logs are returned in page sizes of 100
    + sortOrder: `ASC` (string, optional) - The sort order of the returned audit logs by date. Values: `ASC`, `DESC`. Default: `DESC`.

### Get group level audit logs [POST]
+ Request (application/json)
    + Headers

            Authorization: token API_KEY

    + Attributes (Groups Audit logs filters)

+ Response 200 (application/json; charset=utf-8)

    + Headers

            Link: <https://api.snyk.io/v1/group/4a18d42f-0706-4ad0-b127-24078731fbea/audit?from=2019-07-01&page=1&sortOrder=ASC&to=2019-07-07>; rel=last

    + Body

            [
                {
                    "groupId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "orgId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "userId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "projectId": null,
                    "event": "group.edit",
                    "content": {
                        "before": { "name": "Group Previous Name" },
                        "after": { "name": "Group Current Name" }
                    },
                    "created": "2017-04-11T21:00:00.000Z"
                }
            ]


## Organization level audit logs [/org/{orgId}/audit{?from,to,page,sortOrder}]
+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbea` (string, required) - The organization ID. The `API_KEY` must have access to this organization.
    + from: `2019-07-01` (string, optional) - The date you wish to fetch results from, in the format YYYY-MM-DD. Default is 3 months ago. Please note that logs are only available for past 3 months.
    + to: `2019-07-07` (string, optional) - The date you wish to fetch results until, in the format YYYY-MM-DD. Default is today. Please note that logs are only available for past 3 months.
    + page: `1` (number, optional) - The page of results to request. Audit logs are returned in page sizes of 100.
    + sortOrder: `ASC` (string, optional) - The sort order of the returned audit logs by date. Values: `ASC`, `DESC`. Default: `DESC`.

### Get organization level audit logs [POST]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Audit Logs`

    + Headers

            Authorization: token API_KEY

    + Attributes (Org Audit logs filters)

+ Response 200 (application/json; charset=utf-8)

    + Headers

            Link: <https://api.snyk.io/v1/org/4a18d42f-0706-4ad0-b127-24078731fbea/audit?from=2019-07-01&page=1&sortOrder=ASC&to=2019-07-07>; rel=last

    + Body

            [
                {
                    "groupId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "orgId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "userId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "projectId": null,
                    "event": "org.user.invite",
                    "content": {
                        "email": "someone@snyk.io",
                        "isAdmin": false
                    },
                    "created": "2017-04-11T21:00:00.000Z"
                },
                {
                    "groupId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "orgId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "userId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                    "projectId": null,
                    "event": "org.user.role.edit",
                    "content": {
                        "userPublicId": "4a18d42f-0706-4ad0-b127-24078731fbea",
                        "before": "COLLABORATOR",
                        "after": "ADMIN"
                    },
                    "created": "2017-05-15T06:02:45.497Z"
                }
            ]

# Data Structures

## Org Audit logs filters
+ filters (object, optional) -
    + userId (string, optional) - User public ID. Will fetch only audit logs originated from this user's actions.
    + email (string, optional) - User email address. Will fetch only audit logs originated from this user's actions. Ignored if the userId filter is set.
    + event (enum[string], optional) - Will return only logs for this specific event. Only one of event and excludeEvent may be specified in a request.
        + `api.access`
        + `org.app_bot.create`
        + `org.app.create`
        + `org.app.delete`
        + `org.app.edit`
        + `org.cloud_config.settings.edit`
        + `org.collection.create`
        + `org.collection.delete`
        + `org.collection.edit`
        + `org.create`
        + `org.delete`
        + `org.edit`
        + `org.ignore_policy.edit`
        + `org.integration.create`
        + `org.integration.delete`
        + `org.integration.edit`
        + `org.integration.settings.edit`
        + `org.language_settings.edit`
        + `org.notification_settings.edit`
        + `org.org_source.create`
        + `org.org_source.delete`
        + `org.org_source.edit`
        + `org.policy.edit`
        + `org.project_filter.create`
        + `org.project_filter.delete`
        + `org.project.add`
        + `org.project.attributes.edit`
        + `org.project.delete`
        + `org.project.edit`
        + `org.project.fix_pr.auto_open`
        + `org.project.fix_pr.manual_open`
        + `org.project.ignore.create`
        + `org.project.ignore.delete`
        + `org.project.ignore.edit`
        + `org.project.monitor`
        + `org.project.pr_check.edit`
        + `org.project.remove`
        + `org.project.settings.delete`
        + `org.project.settings.edit`
        + `org.project.stop_monitor`
        + `org.project.tag.add`
        + `org.project.tag.remove`
        + `org.project.test`
        + `org.request_access_settings.edit`
        + `org.sast_settings.edit`
        + `org.service_account.create`
        + `org.service_account.delete`
        + `org.service_account.edit`
        + `org.settings.feature_flag.edit`
        + `org.target.create`
        + `org.target.delete`
        + `org.user.add`
        + `org.user.invite`
        + `org.user.invite.accept`
        + `org.user.invite.revoke`
        + `org.user.invite_link.accept`
        + `org.user.invite_link.create`
        + `org.user.invite_link.revoke`
        + `org.user.leave`
        + `org.user.provision.accept`
        + `org.user.provision.create`
        + `org.user.provision.delete`
        + `org.user.remove`
        + `org.user.role.create`
        + `org.user.role.delete`
        + `org.user.role.details.edit`
        + `org.user.role.edit`
        + `org.user.role.permissions.edit`
        + `org.webhook.add`
        + `org.webhook.delete`
        + `user.org.notification_settings.edit`
    + excludeEvent (enum[string], optional) - Will return logs except logs for this event. Only one of event and excludeEvent may be specified in a request.
        + `api.access`
        + `org.app_bot.create`
        + `org.app.create`
        + `org.app.delete`
        + `org.app.edit`
        + `org.cloud_config.settings.edit`
        + `org.collection.create`
        + `org.collection.delete`
        + `org.collection.edit`
        + `org.create`
        + `org.delete`
        + `org.edit`
        + `org.ignore_policy.edit`
        + `org.integration.create`
        + `org.integration.delete`
        + `org.integration.edit`
        + `org.integration.settings.edit`
        + `org.language_settings.edit`
        + `org.notification_settings.edit`
        + `org.org_source.create`
        + `org.org_source.delete`
        + `org.org_source.edit`
        + `org.policy.edit`
        + `org.project_filter.create`
        + `org.project_filter.delete`
        + `org.project.add`
        + `org.project.attributes.edit`
        + `org.project.delete`
        + `org.project.edit`
        + `org.project.fix_pr.auto_open`
        + `org.project.fix_pr.manual_open`
        + `org.project.ignore.create`
        + `org.project.ignore.delete`
        + `org.project.ignore.edit`
        + `org.project.monitor`
        + `org.project.pr_check.edit`
        + `org.project.remove`
        + `org.project.settings.delete`
        + `org.project.settings.edit`
        + `org.project.stop_monitor`
        + `org.project.tag.add`
        + `org.project.tag.remove`
        + `org.project.test`
        + `org.request_access_settings.edit`
        + `org.sast_settings.edit`
        + `org.service_account.create`
        + `org.service_account.delete`
        + `org.service_account.edit`
        + `org.settings.feature_flag.edit`
        + `org.target.create`
        + `org.target.delete`
        + `org.user.add`
        + `org.user.invite`
        + `org.user.invite.accept`
        + `org.user.invite.revoke`
        + `org.user.invite_link.accept`
        + `org.user.invite_link.create`
        + `org.user.invite_link.revoke`
        + `org.user.leave`
        + `org.user.provision.accept`
        + `org.user.provision.create`
        + `org.user.provision.delete`
        + `org.user.remove`
        + `org.user.role.create`
        + `org.user.role.delete`
        + `org.user.role.details.edit`
        + `org.user.role.edit`
        + `org.user.role.permissions.edit`
        + `org.webhook.add`
        + `org.webhook.delete`
        + `user.org.notification_settings.edit`
    + projectId (string, optional) - Will return only logs for this specific project.

## Groups Audit logs filters
+ filters (object, optional) -
    + userId (string, optional) - User public ID. Will fetch only audit logs originated from this user's actions.
    + email (string, optional) - User email address. Will fetch only audit logs originated from this user's actions. Ignored if the userId filter is set.
    + event (enum[string], optional)- Will return only logs for this specific event. Only one of event and excludeEvent may be specified in a request.
        + `api.access`
        + `group.cloud_config.settings.edit`
        + `group.create`
        + `group.delete`
        + `group.edit`
        + `group.notification_settings.edit`
        + `group.org.add`
        + `group.org.remove`
        + `group.policy.create`
        + `group.policy.delete`
        + `group.policy.edit`
        + `group.request_access_settings.edit`
        + `group.role.create`
        + `group.role.delete`
        + `group.role.edit`
        + `group.service_account.create`
        + `group.service_account.delete`
        + `group.service_account.edit`
        + `group.settings.edit`
        + `group.settings.feature_flag.edit`
        + `group.sso.add`
        + `group.sso.auth0_connection.create`
        + `group.sso.auth0_connection.edit`
        + `group.sso.create`
        + `group.sso.delete`
        + `group.sso.edit`
        + `group.sso.membership.sync`
        + `group.sso.remove`
        + `group.tag.create`
        + `group.tag.delete`
        + `group.user.add`
        + `group.user.remove`
        + `group.user.role.edit`
    + excludeEvent (enum[string], optional) - Will return logs except logs for this event. Only one of event and excludeEvent may be specified in a request.
        + `api.access`
        + `group.cloud_config.settings.edit`
        + `group.create`
        + `group.delete`
        + `group.edit`
        + `group.notification_settings.edit`
        + `group.org.add`
        + `group.org.remove`
        + `group.policy.create`
        + `group.policy.delete`
        + `group.policy.edit`
        + `group.request_access_settings.edit`
        + `group.role.create`
        + `group.role.delete`
        + `group.role.edit`
        + `group.service_account.create`
        + `group.service_account.delete`
        + `group.service_account.edit`
        + `group.settings.edit`
        + `group.settings.feature_flag.edit`
        + `group.sso.add`
        + `group.sso.auth0_connection.create`
        + `group.sso.auth0_connection.edit`
        + `group.sso.create`
        + `group.sso.delete`
        + `group.sso.edit`
        + `group.sso.membership.sync`
        + `group.sso.remove`
        + `group.tag.create`
        + `group.tag.delete`
        + `group.user.add`
        + `group.user.remove`
        + `group.user.role.edit`
    + projectId (string, optional) - Will return only logs for this specific project.
# Group Webhooks

## Intro

> Warning: the webhooks feature is currently in beta. While in this status, we may change the API and the structure of webhook payloads at any time, without notice.

Webhooks allow you to be notified of events taking place in the Snyk system and react to changes in your projects.

Webhooks associate an event type with a URL. When something triggers that event type, Snyk sends an HTTP POST request to the URL with a payload containing information about the event. Currently supported targets/scan types are Open Source and container.

## Who can access this feature?

Only Business and Enterprise customers.

## Configuring webhooks

Webhooks can be configured using our API at organization level, by organization admins.

## Webhook Collection [/org/{orgId}/webhooks]

Snyk sends a `ping` event to the newly configured webhook so you can check you're able to receive the transports. 

### Create a webhook [POST]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list projects for. The `API_KEY` must have access to this organization.

+ Attributes (object)

    + url (string) - Webhooks can only be configured for URLs using the `https` protocol. `http` is not allowed.
    + secret (string) - This is a password you create, that Snyk uses to sign our transports to you, so you be sure the notification is authentic. Your `secret` should: Be a random string with high entropy; Not be used for anything else; Only known to Snyk and your webhook transport consuming code;

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Outbound Webhooks`
        + `Create Outbound Webhooks`

    + Headers

            Authorization: token API_KEY

    + Body

            {
              "url": "https://my.app.com/webhook-handler/snyk123",
              "secret": "a8be22bb7bed43a3ac24de3580093560"
            }

+ Response 200 (application/json; charset=utf-8)
    + Body

            {
              "id": "d3cf26b3-2d77-497b-bce2-23b33cc15362",
              "url": "https://my.app.com/webhook-handler/snyk123",
            }

### List webhooks [GET]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID to list projects for. The `API_KEY` must have access to this organization.

+ Request (application/json; charset=utf-8)
    + Required permissions
        + `View Organization`
        + `View Outbound Webhooks`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Body

            {
              "results": [
              {
                "id": "d3cf26b3-2d77-497b-bce2-23b33cc15362",
                "url": "https://my.app.com/webhook-handler/snyk123",
              }
              ],
              "total": 1
            }

## Webhook [/org/{orgId}/webhooks/{webhookId}]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID the project belongs to. The `API_KEY` must have access to this organization.
    + webhookId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The webhook ID.

### Retrieve a webhook [GET]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Outbound Webhooks`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
    + Body

            {
              "id": "d3cf26b3-2d77-497b-bce2-23b33cc15362",
              "url": "https://my.app.com/webhook-handler/snyk123",
            }

### Delete a webhook [DELETE]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Outbound Webhooks`
        + `Remove Outbound Webhooks`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)

## Ping [/org/{orgId}/webhooks/{webhookId}/ping]

+ Parameters
    + orgId: `4a18d42f-0706-4ad0-b127-24078731fbed` (string, required) - The organization ID the project belongs to. The `API_KEY` must have access to this organization.
    + webhookId: `463c1ee5-31bc-428c-b451-b79a3270db08` (string, required) - The webhook ID.

### Ping a webhook [POST]
+ Request (application/json)
    + Required permissions
        + `View Organization`
        + `View Outbound Webhooks`

    + Headers

            Authorization: token API_KEY

+ Response 200 (application/json; charset=utf-8)
# Data Structures

## Org settings response (object)
+ requestAccess (object, optional) - Will only be returned if `API_KEY` has read access to request access settings.
    + enabled: true (boolean, required) - Whether requesting access to the organization is enabled.

## Org settings request (object)
+ requestAccess (object, optional) - Can only be updated if `API_KEY` has edit access to request access settings.
    + enabled: true (boolean, required) - Whether requesting access to the organization is enabled.

## Notification settings request (object)
+ `new-issues-remediations` (New issues notification setting request)
+ `project-imported` (Simple notification setting request)
+ `test-limit` (Simple notification setting request)
+ `weekly-report` (Simple notification setting request)

## Notification settings response (object)
+ `new-issues-remediations` (Notification setting response)
+ `project-imported` (Simple notification setting response)
+ `test-limit` (Simple notification setting response)
+ `weekly-report` (Simple notification setting response)

## New issues notification setting request (object)
+ enabled: true (boolean, required) - Whether notifications should be sent
+ issueSeverity (enum[string], required) - The severity levels of issues to send notifications for (only applicable for `new-remediations-vulnerabilities` notificationType)
    + Members
        + all (string) - Include all issues
        + high (string) - Include issues which are high and critical severity
    + Sample: high
+ issueType (enum[string], required) - Filter the types of issue to include in notifications (only applicable for `new-remediations-vulnerabilities` notificationType)
    + Members
        + all (string) - Include vulnerability & license issues
        + vuln (string) - Include vulnerability issues
        + license (string) - Include license issues
        + none (string) - Do not notify on any issue type
    + Sample: vuln

## Simple notification setting request (object)
+ enabled: true (boolean, required) - Whether notifications should be sent

## Notification setting response (New issues notification setting request)
+ inherited (boolean) - Whether the setting was found on the requested context directly or inherited from a parent

## Simple notification setting response (Simple notification setting request)
+ inherited (boolean) - Whether the setting was found on the requested context directly or inherited from a parent

## Tag (object)
+ key: `example-tag-key` (string) - Alphanumeric including - and _ with a limit of 30 characters
+ value: `example-tag-value` (string) - Alphanumeric including - and _ with a limit of 50 characters

## Integrations (object)
+ key: `github` (string) - The name of an integration
+ value: `9a3e5d90-b782-468a-a042-9a2073736f0b` - Alphanumeric UUID including - with a limit of 36 characters

# PullRequestAssignment (object)
+ enabled (boolean) - if the organization's project(s) will assign Snyk pull requests.
+ type (AssignmentType) - a string representing the type of assignment your projects require.
+ assignees (array[string], optional) - an array of usernames that have contributed to the organization's project(s).

# AutoRemediationPrs (object)
+ freshPrsEnabled (boolean, optional) - If true, allows automatic remediation of newly identified issues, or older issues where a fix has been identified
+ backlogPrsEnabled (boolean, optional) - If true, allows automatic remediation of prioritized backlog issues
+ backlogPrStrategy (enum[string]) - Determine which issues are fixed in a backlog PR
  + Members
    + `vuln` - Open a backlog PR to fix the highest priority vulnerability
    + `dependency` - Open a backlog PR to fix all issues in the package with the highest priority vulnerability
+ usePatchRemediation (boolean, optional) - If true, allows using patched remediation

# AssignmentType (enum)
+ `auto` - assigns pull requests to any contributor(s) of your organization's projects.
+ `manual` - assigns pull requests to all users defined under **`assignees`**.

## Project attributes (object)
+ criticality (array, optional)
    + (enum[string])
        + Members
            + critical (string)
            + high (string)
            + medium (string)
            + low (string)
        + Sample: high
+ environment (array, optional)
    + (enum[string])
        + Members
            + frontend (string)
            + backend (string)
            + internal (string)
            + external (string)
            + mobile (string)
            + saas (string)
            + onprem (string)
            + hosted (string)
            + distributed (string)
        + Sample: backend, internal
+ lifecycle (array, optional)
     + (enum[string])
        + Members
            + production (string)
            + development (string)
            + sandbox (string)
        + Sample: development
