# cert-enricher
Splunk add on that enriches cert event logs with additional cert data via sha256 fingerprints

## Summary
The cert-enricher add on has been developed for and tested on Splunk version 8.0.5. Cert-enricher implements the Splunk custom search command via the splunk-sdk-python package. This add on provides a new search command called `enrich` that can be used to augment certificate data found in event logs.

## Install Instructions
Note: This add on has only be developed and tested for Ubuntu.

Download this repository as a zip file and transfer it to the machine running your splunk search head. Unzip the repo in the `apps` folder of your Splunk install. Typically this can be found at `/opt/splunk/etc/apps`, but you may need to `echo $SPLUNK_HOME` to locate your install location. In order to make the API calls work you will need to set `API_ID` and `API_SECRET` as system environment variables, or directly modify their `None` default values in `bin/config.py`.

## Usage
The cert-enricher has a simple and intuitive usage flow due to the fact that it inherits from Splunk search commands and implements the Splunk SDK's EventingCommand. `enrich` follows the Splunk Processing Language and can be used in conjunction with other commands with the use of pipes. The typical usage structure is `One or more search criteria | enrich`, but can be augmented with other commands as well. Some examples are provided below:

#### A simple search for all events with host `zuko`
`host="zuko" | enrich`

#### Search for all certificates with host `zuko` and trusted by Apple's Browser
`host="zuko" | enrich | search apple_trusted=True`

#### Search for all certificates from June and sort by timestamp
`* | enrich | search date_month=june | sort _time`

#### Display a table of all cert properties for every cert with type `CERT` and operation `ASSOCIATE`
`type="CERT" operation="ASSOCIATE" | enrich | table *`

## Configuration Options
The cert enricher exposes the following configuration settings via the `config.py` file at `APP_ROOT/bin`:
- API_URL - The endpoint for the API
- API_ID - The API user ID
- API_SECRET - The API secret hash
- API_TIMEOUT - The number of seconds the enrich command will wait for an API response

- LOGGING_LEVEL - Accepts standard python logging levels (CRITICAL, ERROR, WARNING, INFO or DEBUG)
- LOGFILE_PATH - The path to the logfile

- MAX_WORKER_THREADS - The maximum supported number of python threads

## Event Format
The enrich command can be used in any splunk search containing certificate events of the format below. Note that the only requried field structures here are that of `id` and `entity`. Events may contain additional fields or exclude below fields, as long as `id` and `entity` are present.

```
    {
        "id": 8051,
        "type": "CERT",
        "timestamp": "2020-06-01T17:08:29.116Z",
        "operation": "ASSOCIATE",
        "entity": {
            "sha256": "262aeb701360d73b27971292346e7a976ea30e32d34f0363f86d49b47c5583ff"
        }
    }
```

## Assumptions
- Cert-enricher assumes that all events searched on will adhere to the format defined above
- Reasonably fast API response times (under 10 seconds per bulk request of 50)
- Splunk version 8.0.5 on a Linux system
